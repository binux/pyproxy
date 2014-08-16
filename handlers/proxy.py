#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# vim: set et sw=4 ts=4 sts=4 ff=unix fenc=utf8:
# Author: Binux<17175297.hk@gmail.com>
#         http://binux.me
# Created on 2012-12-15 17:18:55

import json
import base64
from .base import *
from tornado import gen
import tornado.httpclient

class ProxyHandler(BaseHandler):
    def get(self):
        method = self.request.method
        url = self.request.uri
        headers = self.request.headers
        body = self.request.body

        if self.request.uri.startswith('http'):
            return self.proxy(method, url, headers, body)

        method = self.get_argument('method', method)
        url = self.get_argument('url', url)
        
        try:
            request = json.loads(self.get_argument('request'))
        except:
            request = {}
        url = request.get('url', url)
        method = request.get('method', method)
        headers = request.get('headers', headers)
        body = request.get('body', body)

        if 'del_headers' in request:
            for key in request['del_headers']:
                if key in headers:
                    del headers[key]

        if 'Host' in headers:
            del headers['Host']
        if body.startswith('base64,'):
            try:
                body = body[7:].decode('base64')
            except:
                pass

        if not url.startswith('http'):
            self.finish('hello world!')
            return

        self.request.method = method
        self.request.uri = url

        return self.proxy(method, url, headers, body)

    @gen.coroutine
    def proxy(self, method, url, headers, body):
        if not self.auth():
            raise HTTPError(404)

        req = tornado.httpclient.HTTPRequest(
                method = method,
                url = url,
                headers = headers,
                body = body,
                decompress_response = False,
                follow_redirects = False,
                allow_nonstandard_methods = True)

        client = tornado.httpclient.AsyncHTTPClient()
        try:
            result = yield client.fetch(req)
        except tornado.httpclient.HTTPError, e:
            if e.response:
                result = e.response
            else:
                self.set_status(502)
                self.write('Bad Gateway error:\n' + str(e))
                self.finish()
                return

        self.set_status(result.code, result.reason)
        if result.headers.get('Transfer-Encoding') == 'chunked':
            del result.headers['Transfer-Encoding']
        self._headers = result.headers
        self.finish(result.body)

    put = get
    post = get
    option = get

    def auth(self):
        if not options.username:
            return True

        username, password = None, None

        if 'Proxy-Authorization' in self.request.headers:
            try:
                method, b64 = self.request.headers['Proxy-Authorization'].split(' ', 1)
                username, password = b64.decode('base64').split(':', 1)
            except:
                pass

        if 'Authorization' in self.request.headers:
            try:
                method, b64 = self.request.headers['Authorization'].split(' ', 1)
                username, password = b64.decode('base64').split(':', 1)
            except:
                pass

        username = self.get_argument('username', username)
        password = self.get_argument('password', password)

        try:
            request = json.loads(self.get_argument('request'))
        except:
            request = {}
        username = request.get('username', username)
        password = request.get('username', password)

        if options.username == username and options.password == password:
            return True

        return False
        
handlers = [
        (".*", ProxyHandler),
        ]
