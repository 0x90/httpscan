#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
# Main setup script
#
# ./setup.py install
#

from setuptools import setup, find_packages

setup(
    name='httpscan',
    version='0.1',
    platforms='any',
    author='090h',
    author_email='root@0x90.ru',
    license='GPL',
    keywords="HTTP Scan",
    url="http://github.com/0x90/httpscan",
    description='Multithreaded HTTP scanner',

    packages=['httpscan'],

    # -> /etc/rc.d/init.d/
    scripts=['httpscan.py', ],

    install_requires=['SQLAlchemy',
                      'cookies',
                      'fake-useragent',
                      'requests'
    ],
)