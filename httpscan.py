#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
# Thanks, for the great manual
# https://medium.com/@thechriskiehl/parallelism-in-one-line-40e9b2b36148
#

__author__ = '090h'
__license__ = 'GPL'

from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser
from multiprocessing.dummy import Pool as ThreadPool, Lock
from pprint import pprint
from sys import exit, stdout
from os import path
import logging

from requests import options, get, head



class Output(object):

    def __init__(self, args):
        self.args = args
        self.lock = Lock()

        # logging.basicConfig()
        self.logger = logging.getLogger('httpscan_logger')
        # for h in list(self.logger.handlers):
        #     self.logger.removeHandler(h)

        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%d/%m/%Y %H:%M:%S')
        # logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%d/%m/%Y %H:%M:%S')

        if args.debug:
            print('Enabling debug logging.')
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)

        if args.log_file is not None:
            handler = logging.FileHandler(args.log_file)
        else:
            handler = logging.StreamHandler(stdout)
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def write(self, url, response):

        self.lock.acquire()

        self.logger.info('%s %s' % (url, response.status_code))

        if self.args.output_csv is not None:
            self.write_csv(url, response)

        if self.args.output_json is not None:
            self.write_json(url, response)

        if self.args.output_xml is not None:
            self.write_xml(url, response)

        if self.args.output_database is not None:
            self.write_database(url, response)

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

    def write_csv(self, url, response):
        # File;Response;Content-Leight
        # blabla.ru/.git/index;200;123124

        pass

    def write_json(self, url, response):
        pass

    def write_xml(self, url, response):
        pass

    def write_database(self, url, response):
        pass


class HttpScanner(object):

    def __init__(self, args):
        self.args = args
        self.output = Output(args)
        self.hosts = self.__file_to_list(args.hosts)
        self.urls = self.__file_to_list(args.urls)
        self.pool = ThreadPool(self.args.threads)

    def __file_to_list(self, filename):
        if not path.exists(filename) or not path.isfile(filename):
            self.output.write_error_log(('File %s not found' % filename))
            exit(-1)
        return filter(lambda x: x is not None and len(x) > 0, open(filename).read().split('\n'))

    def scan_host(self, host):
        """
        Scan urls on the single host
        :param host: host to scan
        :return: response list
        """
        if not host.lower().startswith('http'):
            host = 'https://%s' % host if ':443' in host else 'http://%s' % host

        # logging.debug('host url: %s' % host)
        self.output.write_debug_log('Scanning host: %s' % host)

        if self.args.method == 'auto ':
            # Trying to use OPTIONS request
            response = options(host)
            o = response.headers['allow'] if 'allow' in response.headers else None

            # Determine if HEAD requests is allowed
            if o is not None:
                use_head = False if o.find('HEAD') == -1 else True
            else:
                use_head = False if head(host).status_code == 405 else True

            if use_head:
                self.output.write_debug_log('HEAD is supported for %s' % host)

        elif self.args.method == 'get':
            use_head = False
        else:
            use_head = True


        responses = []
        for short_url in self.urls:
            if host.endswith('/') or short_url.startswith('/'):
                url = host + short_url
            else:
                url = host + '/' + short_url

            # logging.debug('Scanning %s' % url)
            if use_head:
                response = head(url, timeout=self.args.timeout, allow_redirects=self.args.allow_redirects, verify=False)
            else:
                response = get(url, timeout=self.args.timeout, allow_redirects=self.args.allow_redirects, verify=False)

            pprint(response.__dict__)

            # Filter responses
            if (self.args.allow is None and self.args.ignore is None) or \
                    (response.status_code in self.args.allow and response.status_code not in self.args.ignore):
                # Log responses
                self.output.write(url, response)
                responses.append(response)

        return responses

    def scan(self):
        """
        Start scaning process
        :return: List of responses
        """
        results = self.pool.map(self.scan_host, self.hosts)

        # Wait
        self.pool.close()
        self.pool.join()

        return results


def main():
    parser = ArgumentParser('httpscan', description='Multithreaded HTTP scanner', formatter_class=ArgumentDefaultsHelpFormatter, fromfile_prefix_chars='@')

    # main options
    parser.add_argument('hosts', help='hosts file')
    parser.add_argument('urls', help='urls file')

    # scan options
    group = parser.add_argument_group('Scan params')
    group.add_argument('-t', '--timeout', type=int, default=10, help='HTTP scan timeout')
    group.add_argument('-T', '--threads', type=int, default=5, help='threads count')
    group.add_argument('-m', '--method', default='auto', choices=['auto', 'get', 'head'], help='method to use while checking')
    group.add_argument('-r', '--allow-redirects', action='store_true', help='follow redirects')
    group.add_argument('-c', '--cookie', help='cookie to send during scan') # --cookie="blabla=asdasd; vblaba"
    group.add_argument('-u', '--user-agent', help='User-Agent')

    # filter options
    group = parser.add_argument_group('Filter options')
    group.add_argument('-a', '--allow', required=False, nargs='+', type=int, help='allow following HTTP response statuses')
    group.add_argument('-i', '--ignore', required=False, nargs='+', type=int, help='ignore following HTTP response statuses')

    # output options
    group = parser.add_argument_group('Output options')
    # group.add_argument('-d', '--dump',  help='dump response files to directory')
    # group.add_argument('-e', '--execute',  help='execute following command on success')
    group.add_argument('-oD', '--output-database', help='output results to database via SQLAlchemy')
    group.add_argument('-oC', '--output-csv', help='output results to CSV file')
    group.add_argument('-oX', '--output-xml', help='output results to XML file')
    group.add_argument('-oJ', '--output-json', help='output results to JSON file')

    #
    group = parser.add_argument_group('Debug logging options')
    group.add_argument('-D', '--debug', action='store_true', help='debug mode')
    group.add_argument('-L', '--log-file', help='debug log path')
    args = parser.parse_args()
    pprint(args)
    hs = HttpScanner(args)
    res = hs.scan()
    pprint(res)

if __name__ == '__main__':
    main()