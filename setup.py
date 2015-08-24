#!/usr/bin/env python2
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
    keywords="HTTP, scanner asynchronous multithreaded",
    url="http://github.com/0x90/httpscan",
    description='Multithreaded  asynchronous HTTP scanner',
    packages=['httpscan'],
    scripts=['httpscan.py'],
    install_requires=['SQLAlchemy',
                      'SQLAlchemy-Utils',
                      'cookies',
                      'colorama',
                      'gevent',
                      'humanize',
                      'fake-useragent',
                      'requests',
                      'requesocks',
                      'six',
                      'pcapy',
                      'scapy',
                      ]
)