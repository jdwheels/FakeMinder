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

import crypto from 'crypto';
import { IFormCred, IFormCredOptions, IFormCredStatus, ISession, ISessionOptions, IUser, IUserOptions } from './types';

export class User implements IUser {
  public name?: string;
  public password?: string;
  public auth_headers: { [name: string]: string; };
  public login_attempts: number;
  public locked: boolean;

  constructor(options?: Partial<IUserOptions>) {
    if (!options) {
      options = {};
    }

    this.name = options.name;
    this.password = options.password;
    this.auth_headers = options.auth_headers || {};
    this.login_attempts = options.login_attempts || 0;
    this.locked = options.locked || false;
  }

  public failedLogon(max_login_attempts: number) {
    this.login_attempts += 1;
    if (this.login_attempts >= max_login_attempts) {
      this.locked = true;
    }
  }

  public save(data_store: IUserOptions[]) {
    let record: Partial<IUser> | undefined = data_store.find((u) => u.name === this.name);

    if (!record) {
      record = {};
    }

    record.name = this.name;
    record.password = this.password;
    record.auth_headers = this.auth_headers;
    record.login_attempts = this.login_attempts;
    record.locked = this.locked;

    data_store.push(record as IUser);
  }
}

export class Session implements ISession {
  public session_id: string;
  public expiration: any;
  public user: any;

  constructor(options: Partial<ISessionOptions>) {
    if (!options) {
      options = {};
    }

    this.session_id = options.session_id || crypto.randomBytes(16).toString('hex');
    this.user = options.user;
    this.expiration = options.expiration;
  }

  public resetExpiration(session_timeout: number) {
    const new_expiration = new Date(new Date().getTime() + 20 * 60000);
    this.expiration = new_expiration.toJSON();
  }

  public hasExpired() {
    const expiration_date = new Date(this.expiration);
    return (+expiration_date < +new Date());
  }
}

export class FormCred implements IFormCred {
  public formcred_id: string;
  public user?: IUserOptions;
  public status?: keyof IFormCredStatus;
  public target_url?: string;

  constructor(options?: Partial<IFormCredOptions>) {
    if (!options) {
      options = {};
    }

    this.formcred_id = options.formcred_id || crypto.randomBytes(16).toString('base64');
    this.user = options.user;
    this.status = options.status;
    this.target_url = options.target_url;
  }
}

export const FormCredStatus = {
  good_login: 'good_login',
  bad_login: 'bad_login',
  bad_password: 'bad_password',
};
