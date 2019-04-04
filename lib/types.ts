import { Request } from "express";
import { LogLevels } from "npmlog";

export interface IConfig {
  proxy: IFmProxyConfig;
  siteminder: ISiteminderConfig;
  upstreamApps: {
    [name: string]: IUpstreamAppConfig;
  }
  users: IUserOptions[];
}

export type IUrlType = Pick<IUpstreamAppConfig,
  "proxy_pass" | "hostname" | "logoff" | "not_authenticated" | "bad_login" | "bad_password" | "account_locked"
>

export interface IUpstreamAppConfig {
  proxy_pass: string;
  hostname: string;
  port: number;
  logoff: string;
  not_authenticated: string;
  bad_login: string;
  bad_password: string;
  account_locked: string;
  protected_by_default: boolean
  path_filters: Array<{
    url: string;
    protected: boolean;
  }>
}

export interface ISiteminderConfig {
  sm_cookie: string;
  sm_cookie_domain: string;
  formcred_cookie: string;
  formcred_cookie_domain: string;
  userid_field: string;
  password_field: string;
  target_field: string;
  session_expiry_minutes: number;
  max_login_attempts: number;
  smagentname: string;
  login_fcc: string;
}

export interface ISessionOptions {
  session_id: string;
  user: string;
  expiration: Date;
}

export interface IUserOptions {
  name: string;
  password: string;
  auth_headers: {
    [name: string]: string
  }
  login_attempts: number;
  locked: boolean;
}

export interface IFormCredOptions {
  formcred_id: string;
  user: IUserOptions;
  status: keyof IFormCredStatus;
  target_url: string;
}

export interface IFormCredStatus {
  good_login: 'string',
  bad_login: 'string',
  bad_password: 'string'
}

export interface ICliOptions {
  proxy_port: number;
  siteminder_smagentname: string;
  upstream_app_hostname: string;
  upstream_app_port: number;
  logoff_path: string;
  not_authenticated_path: string;
  bad_login_path: string;
  bad_password_path: string;
  account_locked_path: string;
  protected_path: string;
  config_name: string;
}

export interface IUrlConfig {
  protected_by_default: boolean;
  path_filters: IPathFilter[];
}

export interface IPathFilter {
  url: string;
  protected: boolean;
}

export interface IFmProxyConfig {
  port: number;
  upstreamApps: string[];
}

// @ts-ignore
export interface IRequest extends Request {
  fm_session: ISession;
  connection: {
    encrypted: boolean;
  }
}

export interface ISession {
  session_id: string;
  expiration: any;
  user: any;

  resetExpiration(session_timeout: number): void;

  hasExpired(): boolean;
}
export interface IFormCred {
  formcred_id: string;
  user?: IUserOptions;
  status?: keyof IFormCredStatus;
  target_url?: string;
}

export interface ILogger {
  (level: LogLevels | string, prefix: string, message: string, ...args: any[]): void
  silly(prefix: string, message: string, ...args: any[]): void;
  verbose(prefix: string, message: string, ...args: any[]): void;
  info(prefix: string, message: string, ...args: any[]): void;
  http(prefix: string, message: string, ...args: any[]): void;
  warn(prefix: string, message: string, ...args: any[]): void;
  error(prefix: string, message: string, ...args: any[]): void;
}

export type AnyFunction = (...args: any[]) => any;
