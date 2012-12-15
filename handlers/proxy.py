#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# vim: set et sw=4 ts=4 sts=4 ff=unix fenc=utf8:
# Author: Binux<17175297.hk@gmail.com>
#         http://binux.me
# Created on 2012-12-15 17:18:55

from .base import *
import tornado.httpclient

class ProxyHandler(BaseHandler):
    @tornado.web.asynchronous
    def get(self):
        req = tornado.httpclient.HTTPRequest(
                url = self.request.uri,
                method = self.request.method,
                body = self.request.body,
                headers = self.request.headers,
                use_gzip = False,
                follow_redirects = False,
                allow_nonstandard_methods = True)

        client = tornado.httpclient.AsyncHTTPClient()
        try:
            client.fetch(req, self.on_response)
        except tornado.httpclient.HTTPError, e:
            if hasattr(e, 'response') and e.response:
                self.on_response(e.response)
            else:
                self.set_status(502)
                self.write('Bad Gateway error:\n' + str(e))
                self.finish()

    def on_response(self, response):
        if response.error:
            self.set_status(502)
            self.write('Bad Gateway error:\n' + str(response.error))
            self.finish()
        else:
            self.set_status(response.code)
            for key, value in response.headers.iteritems():
                self.set_header(key, value)
            if response.body:
                self._write_buffer.append(response.body)
            self.finish()

    put = get
    post = get
    option = get
        
handlers = [
        (".*", ProxyHandler),
        ]
