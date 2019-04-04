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

import { IConfig, IFmProxyConfig, ISiteminderConfig, IUpstreamAppConfig } from "./types";

const fs = require('fs');

// @ts-ignore
class FmProxy {
  public readonly port: number;
  private upstreamApps: string[];

  constructor(config: IFmProxyConfig) {
    this.port = config.port;
    this.upstreamApps = config.upstreamApps;
  }
}

class UpstreamApp implements IUpstreamAppConfig {
  public proxy_pass: any;
  public readonly hostname: string;
  public readonly port: number;
  public logoff: string;
  public readonly not_authenticated: string;
  public bad_login: string;
  public bad_password: string;
  public account_locked: string;
  public protected_by_default: boolean;
  public path_filters: { url: string; protected: boolean; }[];

  constructor(name: string, config: IUpstreamAppConfig) {
    this.proxy_pass = config.proxy_pass;
    this.hostname = config.hostname;
    this.port = config.port;
    this.logoff = config.logoff;
    this.not_authenticated = config.not_authenticated;
    this.bad_login = config.bad_login;
    this.bad_password = config.bad_password;
    this.account_locked = config.account_locked;
    this.protected_by_default = config.protected_by_default;
    this.path_filters = config.path_filters;
  };
}

class SiteMinder {
  public readonly sm_cookie: string;
  public readonly sm_cookie_domain?: string;
  public readonly formcred_cookie: string;
  public readonly formcred_cookie_domain?: string;
  private userid_field: string;
  private password_field: string;
  private target_field: string;
  public readonly session_expiry_minutes: number;
  public readonly max_login_attempts: number;
  public smagentname: string;
  public readonly login_fcc: string;

  constructor(config: Partial<ISiteminderConfig>) {
    this.sm_cookie = config.sm_cookie || "SMSESSION";
    this.sm_cookie_domain = config.sm_cookie_domain;
    this.formcred_cookie = config.formcred_cookie || "FORMCRED";
    this.formcred_cookie_domain = config.formcred_cookie_domain;
    this.userid_field = config.userid_field || "USERNAME";
    this.password_field = config.password_field || "PASSWORD";
    this.target_field = config.target_field || "TARGET";
    this.session_expiry_minutes = config.session_expiry_minutes || 20;
    this.max_login_attempts = config.max_login_attempts || 3;
    this.smagentname = config.smagentname || "";
    this.login_fcc = config.login_fcc || "/public/siteminderagent/login.fcc";
  };
}

export default class Config {
  // @ts-ignore
  private _config: IConfig = {};

  public load = (filename: string) => {
    this._config = JSON.parse(fs.readFileSync(filename, 'utf8'));
  };

  public proxy = () => {
    return new FmProxy(this._config.proxy);
  };

  public siteminder = () => {
    return new SiteMinder(this._config.siteminder);
  };

  upstreamApp = (name: string): IUpstreamAppConfig => {
    return new UpstreamApp(name, this._config.upstreamApps[name]);
  };

  public users = () => {
    return this._config.users;
  };
}

module.exports = Config;
