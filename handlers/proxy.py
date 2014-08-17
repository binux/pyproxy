#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# vim: set et sw=4 ts=4 sts=4 ff=unix fenc=utf8:
# Author: Binux<17175297.hk@gmail.com>
#         http://binux.me
# Created on 2012-12-15 17:18:55

import re
import json
import base64
import hashlib
import urlparse
from .base import *
from tornado import gen
import tornado.httpclient

class ProxyHandler(BaseHandler):
    set_cookie_re = re.compile(";?\s*(domain|path)\s*=\s*[^,;]+", re.I)

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

        if self.request.path == '/sign' and self.auth(url):
            return self.finish(self.sign(url))

        if not url.startswith('http'):
            return self.finish('hello world!')

        self.request.method = method
        self.request.uri = url

        return self.proxy(method, url, headers, body)

    def sign(self, url):
        parsed = urlparse.urlparse(url)
        return {
            'host_sign': hashlib.md5('%s:%s:%s' % (options.username, options.password, parsed.netloc)).hexdigest()[5:11],
            'path_sign': hashlib.md5('%s:%s:%s:%s' % (options.username, options.password, parsed.netloc, parsed.path)).hexdigest()[5:11],
            'url_sign': hashlib.md5('%s:%s:%s' % (options.username, options.password, url)).hexdigest()[5:11],
            }

    @gen.coroutine
    def proxy(self, method, url, headers, body, **kwargs):
        if not self.auth(url):
            raise HTTPError(403)

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
        if 'set-cookie' in result.headers:
            set_cookie = result.headers.get_list('set-cookie')
            del result.headers['set-cookie']
            for each in set_cookie:
                result.headers.add('set-cookie', self.set_cookie_re.sub('', each))
        self._headers = result.headers
        self.finish(result.body)

    put = get
    post = get
    option = get

    def auth(self, url):
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

        # auth by sign
        sign = self.sign(url)
        for key, value in sign.iteritems():
            if request.get(key, self.get_argument(key, None)) == value:
                return True

        return False
        
handlers = [
        (".*", ProxyHandler),
        ]
