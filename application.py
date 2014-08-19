#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# vim: set et sw=4 ts=4 sts=4 ff=unix fenc=utf8:
# Author: Binux<17175297.hk@gmail.com>
#         http://binux.me
# Created on 2012-12-15 16:11:13

import os.path
import logging
import tornado.web
from tornado.options import define, options

define("bind", default="127.0.0.1", help="addrs that debugger bind to")
define("port", default=8888, help="the port that debugger listen to")
define("username", default="", help="proxy username")
define("password", default="", help="proxy password")
define("debug", default=False, help="debug mode")
define("config", default="", help="config file")

class Application(tornado.web.Application):
    def __init__(self):
        from handlers import handlers, ui_modules, ui_methods
        settings = dict(
                template_path = os.path.join(os.path.dirname(__file__), "tpl"),
                static_path = os.path.join(os.path.dirname(__file__), "static"),
                debug = options.debug,

                ui_modules = ui_modules,
                ui_methods = ui_methods,
                )
        super(Application, self).__init__(handlers, **settings)

if __name__ == "__main__":
    import tornado.options
    from tornado.ioloop import IOLoop
    from tornado.httpserver import HTTPServer

    tornado.options.parse_command_line()
    if options.config:
        tornado.options.parse_config_file(options.config)
    tornado.options.parse_command_line()

    http_server = HTTPServer(Application(), xheaders=True)
    http_server.bind(options.port, options.bind)
    http_server.start()

    logging.info("http server started on %s:%s" % (options.bind, options.port))
    IOLoop.instance().start()
