#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# vim: set et sw=4 ts=4 sts=4 ff=unix fenc=utf8:
# Author: Binux<17175297.hk@gmail.com>
#         http://binux.me
# Created on 2012-12-15 17:18:55

import base64
from .base import *
from tornado import gen
import tornado.httpclient

class ProxyHandler(BaseHandler):
    @gen.coroutine
    def get(self):
        if options.username:
            auth = 'Basic %s' % base64.b64encode('%s:%s' % (options.username, options.password))
            if self.request.headers.get('Proxy-Authorization') != auth:
                raise HTTPError(407)

        req = tornado.httpclient.HTTPRequest(
                url = self.request.uri,
                method = self.request.method,
                body = self.request.body,
                headers = self.request.headers,
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
        
handlers = [
        (".*", ProxyHandler),
        ]
