/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2013 Chris Neave
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

import Cookies from 'cookies';
import { NextFunction } from 'express';
import { IncomingMessage, ServerResponse } from 'http';
import qs from 'querystring';
import util from 'util';
import Config from './config';
import * as Model from './model';
import * as pathfilter from './pathfilter';
import {
  AnyFunction,
  IFormCred,
  ILogger,
  IRequest as Request,
  IResponse as Response,
  ISession,
  ISessionOptions,
  IUrlType,
  IUser,
} from './types';
import * as fm_util from './util';

let log: ILogger;

export default class FakeMinder {
  public readonly config: Config;
  private readonly sessions: {[id: string]: ISession};
  private emptySession: Partial<ISession>;
  private readonly formcred: {[cookie: string]: IFormCred};
  private readonly SESSION_COOKIE: string;
  private readonly FORMCRED_COOKIE: string;

  constructor(filename: string, logger: ILogger) {
    log = logger;

    this.config = new Config();
    this.config.load(filename);

    this.sessions = {};
    this.emptySession = {};
    this.formcred = {};
    this.SESSION_COOKIE = this.config.siteminder().sm_cookie;
    this.FORMCRED_COOKIE = this.config.siteminder().formcred_cookie;
  }

  private _getUrl = (url_type: keyof IUrlType) => {
    return this.config.upstreamApp('sample_target')[url_type];
  }

  private _createNewSession = (new_session: ISession) => {
    this.sessions[new_session.session_id] = new_session;
  }

  private _removeSession = (session_id: string) => {
    log.verbose('fakeminder', 'SessionID %s has ended',  session_id);
    delete(this.sessions[session_id]);
  }

  private _redirectTo = (res: Response, url_type: keyof IUrlType) => {
    const url = this._getUrl(url_type);
    this._redirectToUrl(res, url);
  }

  private _redirectToUrl = (res: Response, url: string) => {
    res.statusCode = 302;
    res.setHeader('Location', url);
    res.end();
  }

  private _setCookie = (req: Request, res: Response, cookie_name: string, cookie_value: string, options?: any) => {
    const cookieJar = new Cookies(req, res);
    cookieJar.set(cookie_name, cookie_value, options);
  }

  private _badRequest = (res: Response, message: string) => {
      res.statusCode = 400;
      res.write(message);
      res.end();
  }

  private _notAuthenticated = (req: Request, res: Response) => {
    let url;

    if (this.config.upstreamApp('sample_target').not_authenticated) {
      url = pathfilter.resolve(req.url, this._getUrl('not_authenticated'));
      url = fm_util.redirectUrlFromRequest(req, url);
      this._redirectToUrl(res, url);
    } else {
      log.warn('#_notAuthenticated', 'Couldn\'t find a redirect URL for not_authenticated');
      res.statusCode = 401;
      res.setHeader('WWW-Authenticate', 'Basic realm="Couldn\'t find a redirect URL for not_authenticated"');
      res.end();
    }
  }

  private redirectOr404 = (req: Request, res: Response, url_type: keyof IUrlType, response_message: string) => {
    let url;

    if (this.config.upstreamApp('sample_target')[url_type]) {
      url = pathfilter.resolve(req.url, this._getUrl(url_type));
      url = fm_util.redirectUrlFromRequest(req, url);
      this._redirectToUrl(res, url);
    } else {
      log.warn('#redirectOr404', 'Couldn\'t find a redirect URL for ' + url_type);
      res.statusCode = 404;
      res.write(response_message);
      res.end();
    }
  }

  private _accountLocked = (req: Request, res: Response) => {
    this.redirectOr404(req, res, 'account_locked', 'Account locked. A redirect URL for account_locked is not defined.');
  }

  private _badLogin = (req: Request, res: Response) => {
    this.redirectOr404(req, res, 'bad_login', 'Bad login. A redirect URL for bad_login is not defined.');
  }

  private _badPassword = (req: Request, res: Response) => {
    this.redirectOr404(req, res, 'bad_password', 'Bad password. A redirect URL for bad_password is not defined.');
  }

  public middleware = (req: IncomingMessage, res: ServerResponse, next: NextFunction) => {
    const func_array: AnyFunction[] = [];
    // var self = this;
    const end_func = () => {
    };
    const next_func = () => {
      const func = func_array.shift();
      if (func) {
        func.call(this, req, res, next_func, end_func);
      }
    };

    func_array.push(this.init);
    func_array.push(this.protected);
    func_array.push(this.logon);
    func_array.push(this.logoff);
    func_array.push(this.end);
    func_array.push(next);

    next_func();
  }

  /** Parse inbound SMSESSION cookie and load session details */
  public init = (req: Request, res: Response, next: NextFunction) => {
    const cookieJar = new Cookies(req, res);
    const smsession = cookieJar.get(this.SESSION_COOKIE);
    const existing_session = this.sessions[smsession];

    if (!smsession || !existing_session) {
      next();
      return;
    }

    req.fm_session = existing_session;
    next();
  }

  /** Handle logon requests by processing form POST data and generating a FORMCRED cookie */
  public logon = (req: Request, res: Response, next: NextFunction, end: () => void) => {
    let post_data: any = '';
    let formcred: IFormCred;
    let user: IUser;
    let smagentname;
    let log_msg;
    let is_logon_request;

    // Guard against requests that are not logon requests.
    is_logon_request = (req.url === this.config.siteminder().login_fcc && req.method === 'POST');
    if (!is_logon_request) { return next(); }
    log.info('#logon', 'Logon request => %s %s', req.method, req.url);

    req.on('data', (data) => {
      post_data += data;
    });

    req.on('end', () => {
      post_data = qs.parse(post_data.toLowerCase());

      // If config dictates that an smagentname is required then validate against the POST data
      // and return a 400 response if no good.
      smagentname = this.config.siteminder().smagentname;
      if (smagentname !== '' && smagentname !== post_data.smagentname) {
        log_msg = util.format('SMAGENTNAME of %s not supplied in logon POST data.', smagentname);
        log.warn('#logon', log_msg);
        this._badRequest(res, log_msg);
        end();
        return;
      }

      formcred = new Model.FormCred();
      this.formcred[formcred.formcred_id] = formcred;
      formcred.target_url = post_data.target;
      this._setCookie(req, res, this.FORMCRED_COOKIE, formcred.formcred_id, {
        domain: this.config.siteminder().formcred_cookie_domain,
      });

      // Search for the user, validate the password and set a status accordingly
      user = this.config.users().find((u) => u.name === post_data.user) as IUser;
      formcred.user = user;
      if (user) {
        if (user.password === post_data.password) {
          formcred.status = Model.FormCredStatus.good_login;
          // Reset the login attempts for the user now they have successfully authenticated.
          user.login_attempts = 0;
        } else {
          log.warn('#logon', 'User %s attempted login with bad password %s', user.name, post_data.password);
          formcred.status = Model.FormCredStatus.bad_password;
        }
      } else {
        log.warn('#logon', 'User with name %s not found', post_data.user);
        formcred.status = Model.FormCredStatus.bad_login;
      }

      this._redirectToUrl(res, post_data.target);
      end();
    });
  }

  /** Handle requests for protected resources. If a login/password change is in process validate accordingly */
  public protected = (req: Request, res: Response, next: NextFunction, options: ISessionOptions) => {
    let auth_headers: {[name: string]: string};
    const cookieJar = new Cookies(req, res);
    const formcred_cookie = cookieJar.get(this.FORMCRED_COOKIE);
    let formcred_session: IFormCred | undefined;
    let new_session: ISession;
    // @ts-ignore
    let user: IUser = {};
    let path_filter;

    // Exit from this function early if the URL is not 'protected'
    path_filter = pathfilter.getPathFilter(this.config.upstreamApp('sample_target'), req.url);
    log.verbose('#protected', 'Path filter match for URL %s => %s', req.url, util.inspect(path_filter));
    if (!path_filter.protected) {
      return next();
    }

    if (this.formcred) {
      formcred_session = this.formcred[formcred_cookie];
    }

    // Check the FORMCRED cookie if one exists and act accordingly
    if (formcred_session !== undefined) {
      log.verbose('#protected', 'Found existing FORMCRED session %s', formcred_session.formcred_id);
      // Remove for formcred session from self before doing any validation.
      // FORMCRED is only a transient value that is not required after this step.
      delete(this.formcred[formcred_cookie]);

      if (formcred_session.user) {
        const sessionName = formcred_session.user.name;
        user = this.config.users().find((u) => u.name === sessionName) as IUser;
        user = new Model.User(user);
        if (user && user.locked) {
          log.warn('#protected', 'Account for user %s is currently locked', user.name);
          this._accountLocked(req, res);
          return;
        }
      }

      switch (formcred_session.status) {
        // Login was successful
        case Model.FormCredStatus.good_login:
          Object.keys(this.sessions).filter((session) => {
            if (formcred_session && formcred_session.user) {
              return this.sessions[session].user.name === formcred_session.user.name;
            } else {
              return false;
            }
          }).forEach((session) => {
            delete(this.sessions[session]);
          });

          user.login_attempts = 0;
          user.save(this.config.users());

          new_session = new Model.Session(options);
          new_session.resetExpiration(this.config.siteminder().session_expiry_minutes);
          new_session.user = formcred_session.user;
          this._createNewSession(new_session);
          req.fm_session = new_session;
          log.info('#protected', 'New session %s created for user %s', new_session.session_id, user.name);
          break;

        case Model.FormCredStatus.bad_login:
          this._badLogin(req, res);
          return;

        case Model.FormCredStatus.bad_password:
          user.failedLogon(this.config.siteminder().max_login_attempts);
          user.save(this.config.users());

          // Check whether the user is locked for a second time now they have failed
          // a login attempt.
          if (user.locked) {
            log.warn('#protected', 'Account for user %s is currently locked', user.name);
            this._accountLocked(req, res);
          } else {
            this._badPassword(req, res);
          }

          return;
      }
    } else if (!req.fm_session) {
      log.warn('#protected', 'Session not found');
      return this._notAuthenticated(req, res);
    } else if (req.fm_session.hasExpired()) {
      log.warn('#protected', 'Session %s has expired', req.fm_session.session_id);
      return this._notAuthenticated(req, res);
    }

    auth_headers = req.fm_session.user.auth_headers;

    // If there are auth_headers then add them to the request.
    if (auth_headers) {
      Object.keys(auth_headers).forEach((header) => {
        req.headers[header] = auth_headers[header];
      });
      log.verbose('#protected', 'Adding headers to request => %s',  util.inspect(auth_headers));
    }

    next();
  }

  public logoff = (req: Request, res: Response, next: NextFunction) => {
    const current_session = req.fm_session;

    if (req.url === this._getUrl('logoff')) {
      // Only set an SMSESSION cookie for protected resources the user has access to.
      if (current_session) {
        this._removeSession(current_session.session_id);
        log.verbose('#info', 'Logged off from session ID %s', current_session.session_id);
      }
      this._setCookie(req, res, this.SESSION_COOKIE, 'LOGGEDOFF');
      // Remove the current session from the request to prevent processing it further.
      delete(req.fm_session);
    }

    next();
  }

  /** Set an SMSESSION cookie if required */
  public end = (req: Request, res: Response, next: NextFunction) => {
    if (req.fm_session) {
      req.fm_session.resetExpiration(this.config.siteminder().session_expiry_minutes);
      this._setCookie(req, res, this.SESSION_COOKIE, req.fm_session.session_id, {
        domain: this.config.siteminder().sm_cookie_domain,
      });
      log.verbose('#end', 'SessionID %s has expiration reset to %s',
        req.fm_session.session_id, req.fm_session.expiration);
    }

    next();
  }
}
