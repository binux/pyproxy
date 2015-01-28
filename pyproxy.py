#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# vim: set et sw=4 ts=4 sts=4 ff=unix fenc=utf8:
# Author: Binux<17175297.hk@gmail.com>
#         http://binux.me
# Created on 2012-12-15 16:11:13

import logging
import tornado.web
from tornado.options import define, options

define("bind", default="127.0.0.1", help="addrs that debugger bind to")
define("port", default=8888, help="the port that debugger listen to")
define("username", default="", help="proxy username")
define("password", default="", help="proxy password")
define("debug", default=False, help="debug mode")
define("config", default="", help="config file")

import re
import json
import hashlib
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse
from tornado import gen
from tornado.web import HTTPError
from tornado.ioloop import IOLoop
import tornado.tcpclient
import tornado.httpclient


class ProxyHandler(tornado.web.RequestHandler):
    SUPPORTED_METHODS = ['GET', 'POST', 'CONNECT', 'PUT', 'OPTION']
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
        callback = self.get_argument('callback', None)
        
        try:
            request = json.loads(self.get_argument('request', self.request.body))
        except:
            request = {}
        url = request.get('url', url)
        method = request.get('method', method)
        headers = request.get('headers', headers)
        body = request.get('body', body)
        callback = request.get('callback', callback)

        if 'del_headers' in request:
            for key in request['del_headers']:
                if key in headers:
                    del headers[key]

        for keyword in ('Host', 'Content-Type', 'Content-Length'):
            if keyword in headers:
                del headers[keyword]
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

        return self.proxy(method, url, headers, body, _callback=callback)

    put = get
    post = get
    option = get

    def sign(self, url):
        parsed = urlparse(url)
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
        except tornado.httpclient.HTTPError as e:
            if e.response:
                result = e.response
            else:
                self.set_status(502)
                self.write('Bad Gateway error:\n' + str(e))
                self.finish()
                raise gen.Return()

        self.set_status(result.code, result.reason)
        if result.headers.get('Transfer-Encoding') == 'chunked':
            del result.headers['Transfer-Encoding']
        if 'set-cookie' in result.headers:
            set_cookie = result.headers.get_list('set-cookie')
            del result.headers['set-cookie']
            for each in set_cookie:
                result.headers.add('set-cookie', self.set_cookie_re.sub('', each))

        if kwargs.get('_callback'):
            self.set_header('Content-Type', 'application/javascript')
            self.finish('%s(%s)' % (json.dumps(kwargs['_callback']), json.dumps(result.body)))
        else:
            self._headers = result.headers
            self.finish(result.body)

    def auth(self, url):
        if not options.username:
            return True

        username, password = None, None

        if not (username and password) and 'Proxy-Authorization' in self.request.headers:
            try:
                method, b64 = self.request.headers['Proxy-Authorization'].split(' ', 1)
                username, password = b64.decode('base64').split(':', 1)
            except:
                pass

        if not (username and password) and 'Authorization' in self.request.headers:
            try:
                method, b64 = self.request.headers['Authorization'].split(' ', 1)
                username, password = b64.decode('base64').split(':', 1)
            except:
                pass

        if not (username and password):
            username = self.get_argument('username', username)
            password = self.get_argument('password', password)

        if not (username and password):
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

    @gen.coroutine
    def connect(self):
        url = self.request.uri
        if not self.auth(url):
            raise HTTPError(403)

        try:
            host, port = self.request.uri.split(':')
            remote = yield gen.with_timeout(IOLoop.current().time()+10, tornado.tcpclient.TCPClient().connect(host, int(port)))
        except gen.TimeoutError as e:
            raise HTTPError(504)

        self._auto_finish = False
        client = self.request.connection.detach()
        yield client.write(b'HTTP/1.0 200 Connection established\r\n\r\n')

        fw = remote.set_close_callback(gen.Callback(remote))
        client.read_until_close(lambda x: x, streaming_callback=lambda x: remote.write(x))
        remote.read_until_close(lambda x: x, streaming_callback=lambda x: client.write(x))

        yield [
                gen.Task(client.set_close_callback),
                gen.Task(remote.set_close_callback),
                ]
        self._log()

class Application(tornado.web.Application):
    def __init__(self):
        settings = dict(
                debug = options.debug,
                )
        super(Application, self).__init__([ (".*", ProxyHandler), ], **settings)

def main(**kwargs):
    import tornado.options
    from tornado.ioloop import IOLoop
    from tornado.httpserver import HTTPServer

    tornado.options.parse_command_line()
    if options.config:
        tornado.options.parse_config_file(options.config)
    tornado.options.parse_command_line()

    for key in kwargs:
        setattr(options, key, kwargs[key])

    http_server = HTTPServer(Application(), xheaders=True)
    http_server.bind(options.port, options.bind)
    http_server.start()

    logging.info("http server started on %s:%s" % (options.bind, options.port))
    IOLoop.instance().start()

if __name__ == "__main__":
    main()
