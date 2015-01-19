#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
# Dummy Multithreaded HTTP scanner.
# Not properly tested and bugfixed.
# Feel free to contribute.
#
# Usage example:
#       ./httpscan.py hosts.txt urls.txt --threads 5 -oC test.csv -r -R -D -L scan.log
#
__author__ = '090h'
__license__ = 'GPL'

from logging import StreamHandler, FileHandler, Formatter, getLogger, INFO, DEBUG, basicConfig
from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser
from multiprocessing.dummy import Pool as ThreadPool, Lock
from sys import exit
from os import path
from pprint import pprint
from datetime import datetime

from csv import writer, QUOTE_ALL
from json import dumps
import io

import httplib
import cookielib

# External dependencied
from requests import get, packages
from cookies import Cookies
from fake_useragent import UserAgent


class Output(object):
    def __init__(self, args):
        self.args = args
        self.lock = Lock()

        # Logger init
        self.logger = getLogger('httpscan_logger')
        self.logger.setLevel(DEBUG if args.debug else INFO)
        handler = StreamHandler() if args.log_file is None else FileHandler(args.log_file)
        handler.setFormatter(Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%d/%m/%Y %H:%M:%S'))
        self.logger.addHandler(handler)

        # Requests lib debug
        if args.debug:
            # these two lines enable debugging at httplib level (requests->urllib3->httplib)
            # you will see the REQUEST, including HEADERS and DATA, and RESPONSE with HEADERS but without DATA.
            # the only thing missing will be the response.body which is not logged.
            # httplib.HTTPConnection.debuglevel = 1
            httplib.HTTPConnection.debuglevel = 5
            packages.urllib3.add_stderr_logger()

            basicConfig() # you need to initialize logging, otherwise you will not see anything from requests
            getLogger().setLevel(DEBUG)
            requests_log = getLogger("requests.packages.urllib3")
            requests_log.setLevel(DEBUG)
            # handler = FileHandler('requests.log') # TODO: fix it
            # handler.setFormatter(Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%d/%m/%Y %H:%M:%S'))
            # requests_log.addHandler(handler)
            requests_log.propagate = True
        else:
            # Surpress InsecureRequestWarning: Unverified HTTPS request is being made
            packages.urllib3.disable_warnings()

        # CSV output
        self.csv = None
        if args.output_csv is not None:
            self.csv = writer(open(args.output_csv, 'wb'), delimiter=';', quoting=QUOTE_ALL)
            self.csv.writerow(['url', 'code', 'length'])

        # JSON output
        self.json = None
        if args.output_json is not None:
            self.json = io.open(args.output_json, 'w', encoding='utf-8')

        # TODO: XML output
        # if args.output_xml is not None:
        #     pass

        # TODO: Database output
        # if args.output_database is not None:
        #     pass

    def write(self, url, response):
        self.lock.acquire()
        length = int(response.headers['content-length']) if 'content-length' in response.headers else len(response.text)
        self.logger.info('%s %s %i' % (url, response.status_code, len(response.text)))

        row = [url, response.status_code, length]
        if self.csv is not None:
            self.csv.writerow(row)

        if self.json is not None:
            jdict = {'url': row[0], 'code': row[1], 'length': row[2]}
            self.json.write(unicode(dumps(jdict, ensure_ascii=False)))

        # if self.args.output_xml is not None:
        #     # TODO: XML output
        #     pass
        #
        # if self.args.output_database is not None:
        #     # TODO: Database output
        #     pass

        self.lock.release()

    def write_log(self, msg):
        self.lock.acquire()
        self.logger.info(msg)
        self.lock.release()

    def write_debug_log(self, msg):
        self.lock.acquire()
        self.logger.debug(msg)
        self.lock.release()

    def write_error_log(self, msg):
        self.lock.acquire()
        self.logger.error(msg)
        self.lock.release()


class HttpScanner(object):
    def __init__(self, args):
        self.args = args
        self.output = Output(args)
        self.pool = ThreadPool(self.args.threads)

        # Reading files
        hosts = self.__file_to_list(args.hosts)
        urls = self.__file_to_list(args.urls)

        # Generating full url list
        self.urls = []
        for host in hosts:
            host = 'https://%s' % host if ':443' in host else 'http://%s' % host if not host.lower().startswith(
                'http') else host
            for url in urls:
                full_url = host + url if host.endswith('/') or url.startswith('/') else host + '/' + url
                if full_url not in self.urls:
                    self.urls.append(full_url)

        print('%i hosts %i urls loaded, %i urls to scan' % (len(hosts), len(urls), len(self.urls)))

        # Auth
        if self.args.auth is None:
            self.auth = ()
        else:
            items = self.args.auth.split(':')
            self.auth = (items[0], items[1])

        # Cookies
        self.cookies = {}
        if self.args.cookies is not None:
            self.cookies = Cookies.from_request(self.args.cookies)

        if self.args.load_cookies is not None:
            if not path.exists(self.args.load_cookies) or not path.isfile(self.args.load_cookies):
                self.output.write_error_log('Could not find cookie file: %s' % self.args.load_cookies)
                exit(-1)

            self.cookies = cookielib.MozillaCookieJar(self.args.load_cookies)
            self.cookies.load()

        # User-Agent
        self.ua = UserAgent() # if self.args.random_agent else None

    def __file_to_list(self, filename):
        if not path.exists(filename) or not path.isfile(filename):
            self.output.write_error_log(('File %s not found' % filename))
            exit(-1)
        return filter(lambda x: x is not None and len(x) > 0, open(filename).read().split('\n'))

    def scan_url(self, url):
        self.output.write_debug_log('Scanning  %s' % url)

        headers = {}
        if self.args.user_agent is not None:
            headers = {'User-agent': self.args.user_agent}
        if self.args.random_agent:
            headers = {'User-agent': self.ua.random}
        try:
            response = get(url, timeout=self.args.timeout, headers=headers, allow_redirects=self.args.allow_redirects,
                       verify=False, cookies=self.cookies, auth=self.auth)
        except:
            self.output.write_error_log('Error while quering %s' % url)
            return None

        # Filter responses and save responses that are matching
        if (self.args.allow is None and self.args.ignore is None) or \
                (response.status_code in self.args.allow and response.status_code not in self.args.ignore):
            self.output.write(url, response)

        return response

    def scan(self):
        results = self.pool.map(self.scan_url, self.urls)
        # Wait
        self.pool.close()
        self.pool.join()

        return results


def main():
    parser = ArgumentParser('httpscan', description='Multithreaded HTTP scanner',
                            formatter_class=ArgumentDefaultsHelpFormatter, fromfile_prefix_chars='@')

    # main options
    parser.add_argument('hosts', help='hosts file')
    parser.add_argument('urls', help='urls file')

    # scan options
    group = parser.add_argument_group('Scan params')
    group.add_argument('-t', '--timeout', type=int, default=10, help='HTTP scan timeout')
    group.add_argument('-T', '--threads', type=int, default=5, help='threads count')
    group.add_argument('-r', '--allow-redirects', action='store_true', help='follow redirects')
    group.add_argument('-a', '--auth', help='HTTP Auth user:password')
    group.add_argument('-c', '--cookies', help='cookies to send during scan')
    group.add_argument('-C', '--load-cookies', help='load cookies from specified file')
    group.add_argument('-u', '--user-agent', help='User-Agent to use')
    group.add_argument('-R', '--random-agent', action='store_true', help='use random User-Agent')

    # filter options
    group = parser.add_argument_group('Filter options')
    group.add_argument('-A', '--allow', required=False, nargs='+', type=int,
                       help='allow following HTTP response statuses')
    group.add_argument('-I', '--ignore', required=False, nargs='+', type=int,
                       help='ignore following HTTP response statuses')

    # Output options
    group = parser.add_argument_group('Output options')
    group.add_argument('-oC', '--output-csv', help='output results to CSV file')
    group.add_argument('-oJ', '--output-json', help='output results to JSON file')
    # group.add_argument('-oD', '--output-database', help='output results to database via SQLAlchemy')
    # group.add_argument('-oX', '--output-xml', help='output results to XML file')


    # Debug and logging options
    group = parser.add_argument_group('Debug logging options')
    group.add_argument('-D', '--debug', action='store_true', help='write program debug output to file')
    group.add_argument('-L', '--log-file', help='debug log path')
    args = parser.parse_args()
    # pprint(args)

    start = datetime.now()
    HttpScanner(args).scan()
    print('Scan started %s' % start)
    print('Scan finished %s' % datetime.now())

if __name__ == '__main__':
    main()