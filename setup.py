#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# vim: set et sw=4 ts=4 sts=4 ff=unix fenc=utf8:
# Author: Binux<roy@binux.me>
#         http://binux.me
# Created on 2015-01-28 21:31:13

from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()


setup(
    name='pyproxy',
    version='0.1',

    description='An HTTP proxy server with API on tornado, just in one file!',
    long_description=long_description,

    url='https://github.com/binux/pyproxy',

    author='Roy Binux',
    author_email='roy@binux.me',

    license='Apache License, Version 2.0',

    classifiers=[
        'Development Status :: 4 - Beta',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',

        'License :: OSI Approved :: Apache Software License',

        'Intended Audience :: Developers',
        'Operating System :: OS Independent',

        'Topic :: Internet :: WWW/HTTP',
    ],

    keywords='proxy https http',

    packages=find_packages(exclude=[]),

    install_requires=[
        'tornado>=2.1.1',
    ],

    entry_points={
        'console_scripts': [
            'pyproxy=pyproxy:main'
        ]
    },
)
