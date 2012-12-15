#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# vim: set et sw=4 ts=4 sts=4 ff=unix fenc=utf8:
# Author: Binux<17175297.hk@gmail.com>
#         http://binux.me
# Created on 2012-12-15 16:19:06

from .base import *

class IndexHandler(BaseHandler):
    def get(self):
        self.write("hello world!")
        self.finish()

handlers = [
        ('/', IndexHandler),
        ]
