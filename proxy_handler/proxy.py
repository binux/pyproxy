#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# vim: set et sw=4 ts=4 sts=4 ff=unix fenc=utf8:
# Author: Binux<17175297.hk@gmail.com>
#         http://binux.me
# Created on 2012-12-15 17:18:55

import logging
import tornado.httpclient

class ProxyHandler(object):
    def __init__(self, request):
        self.request = request
        if getattr(self.request, "connection", None):
            self.request.connection.stream.set_close_callback(
                self.on_connection_close)

    def _build_remote_request(self, request):
        req = tornado.httpclient.HTTPRequest(
                url = request.uri,
                method = request.method,
                body = request.body,
                headers = request.headers,
                use_gzip = False,
                follow_redirects = False,
                allow_nonstandard_methods = True,
                connect_timeout = 0,
                request_timeout = 0)
        return req

    def _execute(self):
        self.remote_request = self._build_remote_request(self.request)
        self.remote_request.straming_callback = self.on_chunk
        self.remote_request.header_callback = self.on_headers

        http_client = tornado.httpclient.AsyncHTTPClient()
        try:
            http_client.fetch(req, self.on_response)
        except tornado.httpclient.HTTPError, e:
            if hasattr(e, 'response') and e.response:
                self.on_response(e.response)
            else:
                self.set_status(502)
                self.write('Bad Gateway error:\n' + str(e))
                self.finish()

    def on_headers(self, data):
        pass

    def on_chunk(self, data):
        pass

    def on_response(self, response):
        pass


    def on_connection_close(self):
        pass

    def set_request_headers(self):
        pass

    def set_response_headers(self):
        pass

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
