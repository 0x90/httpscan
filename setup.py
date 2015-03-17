#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
# Main setup script
# ./setup.py install

from setuptools import setup

setup(
    name='httpscan',
    version='0.5',
    platforms='any',
    author='@090h',
    author_email='root@0x90.ru',
    license='GPL',
    keywords="HTTP, scanner, asynchronous, multithread",
    url="http://github.com/0x90/httpscan",
    description='Multithreaded  asynchronous HTTP scanner',
    packages=['httpscan'],
    scripts=['httpscan.py'],
    install_requires=['SQLAlchemy',
                      'SQLAlchemy-Utils',
                      'cookies',
                      'colorama',
                      'gevent'
                      'fake-useragent',
                      'requests',
                      ]
)