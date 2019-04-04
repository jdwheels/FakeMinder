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

import { IRequest } from "./types";

var http = require('http');
var url = require('url');
var httpProxy = require('http-proxy');
import FakeMinder from './fakeminder';
import ErrnoException = NodeJS.ErrnoException;
import { Request, Response } from "express";
var log = require('./logger');
var util = require('util');

module.exports.start = function(config_file: string) {
  if (!require('fs').existsSync(config_file)) {
    log.error('#server', 'Config file %s does not exist', config_file);
    process.exit();
  }

  var fm = new FakeMinder(config_file, log);
  var port = fm.config.proxy().port;
  var upstreamApp = fm.config.upstreamApp('sample_target');

  var proxy = httpProxy.createProxyServer();
  var server = http.createServer(function(req: IRequest, res: Response) {
    fm.middleware(req, res, function() {
      proxy.web(req, res, {
        target: {
          host: upstreamApp.hostname,
          port: upstreamApp.port
        }
      });
    });
  }).listen(port);

  log.info('#server', 'Listening on port ' + port);

  proxy.on('error', function(err: ErrnoException, req: Request, res: Response) {
    if (err.code === 'ECONNREFUSED') {
      log.error('#server', 'Connection refused! Make sure the target application %s:%d is running', upstreamApp.hostname, upstreamApp.port);
    }
  });

  proxy.on('proxyRes', function(req: IRequest, res: Response, response: Response) {
    var message = util.format('%s %s => %d', req.method, req.url, response.statusCode);

    if (response.statusCode >= 500) {
      log.error('#server', message);
    } else if (response.statusCode >= 400) {
      log.warn('#server', message);
    } else {
      log.verbose('#server', message);
    }
  });
};