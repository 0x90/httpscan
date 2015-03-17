#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
# Multithreaded asynchronous HTTP scanner.
# Feel free to contribute.
#
# Usage example:
# ./httpscan.py hosts.txt urls.txt -T 10 -A 200 -r -U  -L scan.log --tor -oC test.csv -oD sqlite:///test.db
#

__author__ = '@090h'
__license__ = 'GPL'
__version__ = '0.5'

# Check Python version
from platform import python_version

if python_version() == '2.7.9':
    print("Gevent doesn't work in proper way under Python 2.7.9")
    print("https://github.com/gevent/gevent/issues/477")
    exit(-1)

# Gevent monkey patching
from gevent import monkey
monkey.patch_all()

# Basic dependencies
from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser
from sys import exit
from os import path, makedirs
from datetime import datetime
from urlparse import urlparse, urljoin
from csv import writer, QUOTE_ALL
from json import dumps
from cookielib import MozillaCookieJar
from httplib import HTTPConnection
import logging
import signal
import io

# External dependencies
from sqlalchemy_utils.functions import create_database, database_exists
from sqlalchemy import create_engine, Table, Column, Integer, String, MetaData
from requests import ConnectionError, HTTPError, Timeout, TooManyRedirects
from requests.adapters import HTTPAdapter, DEFAULT_RETRIES
from requests import packages, get
from requesocks import session
from cookies import Cookies
from fake_useragent import UserAgent
from colorama import init, Fore
from gevent.queue import JoinableQueue
from gevent.lock import RLock
from gevent import spawn
import gevent

# Scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.layers.inet import ICMP, TCP, IP


def strnow(format='%d.%m.%Y %H:%M:%S'):
    """
    Current datetime to string
    :param format: format string for output
    :return: string for current datetime
    """
    return datetime.now().strftime(format)


def deduplicate(seq):
    """
    Deduplicate list
    :param seq: list to deduplicate
    :return: deduplicated list
    """
    seen = set()
    seen_add = seen.add
    return [x for x in seq if not (x in seen or seen_add(x))]


class HttpScannerOutput(object):
    def __init__(self, args):
        # TODO: make separate queues for fast logging
        self.args = args
        self.lock = RLock()
        self.log_lock = RLock()

        # Colorama init
        init()

        # Initialise logging
        self._init_logger()
        self._init_requests_output()

        # Initialise output
        self._init_csv()
        self._init_json()
        self._init_dump()
        self._init_db()

        # Stats
        self.urls_scanned = 0

    def _init_logger(self):
        """
        Init logger
        :return: None
        """
        if self.args.log_file is not None:
            self.logger = logging.getLogger('httpscan_logger')
            self.logger.setLevel(logging.DEBUG if self.args.debug else logging.INFO)
            handler = logging.FileHandler(self.args.log_file)
            handler.setFormatter(
                logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%d.%m.%Y %H:%M:%S'))
            self.logger.addHandler(handler)
        else:
            self.logger = None

    def _init_requests_output(self):
        """
        Init requests library output
        :return: None
        """
        if self.args.debug:
            # Enable requests lib debug output
            HTTPConnection.debuglevel = 5
            packages.urllib3.add_stderr_logger()
            logging.basicConfig()
            logging.getLogger().setLevel(logging.DEBUG)
            requests_log = logging.getLogger("requests.packages.urllib3")
            requests_log.setLevel(logging.DEBUG)
            requests_log.propagate = True
        else:
            # Surpress InsecureRequestWarning: Unverified HTTPS request is being made
            packages.urllib3.disable_warnings()

    def _init_csv(self):
        """
        Initialise CSV output
        :return:
        """
        if self.args.output_csv is None:
            self.csv = None
        else:
            # TODO: check if file exists
            self.csv = writer(open(self.args.output_csv, 'wb'), delimiter=';', quoting=QUOTE_ALL)
            self.csv.writerow(['url', 'status', 'length', 'headers'])

    def _init_json(self):
        """
        Initialise JSON output
        :return: None
        """
        self.json = None if self.args.output_json is None else io.open(self.args.output_json, 'w', encoding='utf-8')

    def _init_dump(self):
        """
        Initialise dump folder
        :return: None
        """
        self.dump = path.abspath(self.args.dump) if self.args.dump is not None else None
        if self.dump is not None and not path.exists(self.dump):
            makedirs(self.dump)

    def _init_db(self):
        """
        Initialise database output. Create database and table if missing.
        :return: None
        """
        if self.args.output_database is None:
            self.engine = None
            return

        # Check and create database if needed
        if not database_exists(self.args.output_database):
            create_database(self.args.output_database, encoding='utf8')

        # Create table
        self.engine = create_engine(self.args.output_database)
        self.metadata = MetaData()
        self.scan_table = Table('httpscan', self.metadata,
                                Column('id', Integer, primary_key=True),
                                Column('url', String),
                                Column('status', Integer),
                                Column('length', Integer),
                                Column('headers', String)
                                )
        self.metadata.create_all(self.engine)

    def _parse_response(self, url, response):
        """
        Parse url and response to dictionary
        :param url:
        :param response:
        :return: None
        """
        if response is None:
            return {'url': url,
                    'status': -1,
                    'length': -1,
                    'headers': None
                    }

        try:
            length = int(response.headers['content-length']) if 'content-length' in response.headers else len(
                response.text)
        except Exception as exception:
            self.write_log("Exception while getting content length for URL: %s Exception: %s" % (url, str(exception)))
            length = 0
        return {'url': url,
                'status': response.status_code,
                'length': length,
                'headers': str(response.headers)
                }

    def write(self, worker_id, url, response, exception):
        """
        Write url and response to output asynchronously
        :param url:
        :param response:
        :return: None
        """
        spawn(self.write_func, worker_id, url, response, exception)

    def write_func(self, worker_id, url, response, exception):
        """
        Write url and response to output synchronously
        :param url: url scanned
        :param response: response to parse
        :return: None
        """
        # Acquire lock
        self.lock.acquire()
        parsed = self._parse_response(url, response)

        # Calculate progreess
        self.urls_scanned += 1
        percentage = '{percent:.2%}'.format(percent=float(self.urls_scanned) / self.args.urls_count)
        # TODO: add detailed stats

        # Generate and print colored output
        out = '[%s] [worker:%s] [%s]\t%s -> %i' % (strnow(), worker_id, percentage, parsed['url'], parsed['status'])
        if exception is not None:
            out += '(%s)' % str(exception)
        if parsed['status'] == 200:
            print(Fore.GREEN + out + Fore.RESET)
        elif 400 <= parsed['status'] < 500 or parsed['status'] == -1:
            print(Fore.RED + out + Fore.RESET)
        else:
            print(Fore.YELLOW + out + Fore.RESET)

        # Write to log file
        if self.logger is not None:
            out = '[worker:%s] %s %s %i' % (worker_id, url, parsed['status'], parsed['length'])
            if exception is None:
                self.logger.info(out)
            else:
                self.logger.error("%s %s" % (out, str(exception)))

        # Check for exception
        if exception is not None:
            self.lock.release()
            return

        # Filter responses and save responses that are matching ignore, allow rules
        if (self.args.allow is None and self.args.ignore is None) or \
                (self.args.allow is not None and parsed['status'] in self.args.allow) or \
                (self.args.ignore is not None and parsed['status'] not in self.args.ignore):

            # Write to CSV file
            if self.csv is not None:
                self.csv.writerow([parsed['url'], parsed['status'], parsed['length'], parsed['headers']])

            # Write to JSON file
            if self.json is not None:
                self.json.write(unicode(dumps(parsed, ensure_ascii=False)))

            # Save contents to file
            if self.dump is not None:
                self._write_dump(url, response)

            # Write to database
            if self.engine is not None:
                self._write_db(parsed)

        # Realse lock
        self.lock.release()

    def _write_dump(self, url, response):
        """
        Write dump
        :param url: URL scanned
        :param response: response
        :return: None
        """
        if response is None:
            return

        # Generate folder and file path
        parsed = urlparse(url)
        host_folder = path.join(self.dump, parsed.netloc)
        p, f = path.split(parsed.path)
        folder = path.join(host_folder, p[1:])
        if not path.exists(folder):
            makedirs(folder)
        filename = path.join(folder, f)

        # Get all content
        try:
            content = response.content
        except Exception as exception:
            self.write_log('Failed to get content for %s Exception: %s' % (url, str(exception)))
            return

        # Save contents to file
        f = open(filename, 'wb')
        f.write(content)
        f.close()

    def _write_db(self, parsed):
        # TODO: check if url exists in table
        self.scan_table.insert()
        self.engine.execute(self.scan_table.insert().execution_options(autocommit=True), parsed)

    def write_log(self, msg, loglevel=logging.INFO):
        """
        Write message to log file
        :param msg:
        :param loglevel:
        :return: None
        """
        if self.logger is None:
            return

        self.log_lock.acquire()
        if loglevel == logging.INFO:
            self.logger.info(msg)
        elif loglevel == logging.DEBUG:
            self.logger.debug(msg)
        elif loglevel == logging.ERROR:
            self.logger.error(msg)
        elif loglevel == logging.WARNING:
            self.logger.warning(msg)

        self.log_lock.release()

    def print_and_log(self, msg, loglevel=logging.INFO):
        # TODO: make separate logging
        print('[%s] %s' % (strnow(), msg))
        self.write_log(msg, loglevel)


class HttpScanner(object):
    def __init__(self, args):
        """
        Initialise HTTP scanner
        :param args:
        :return:
        """
        self.args = args
        self.output = HttpScannerOutput(args)
        self._init_scan_options()

        # Reading files
        self.output.write_log("Reading files and deduplicating.", logging.INFO)
        self.hosts = self._file_to_list(args.hosts, True)
        self.urls = self._file_to_list(args.urls, True)

        # Calculations
        urls_count = len(self.urls)
        hosts_count = len(self.hosts)
        full_urls_count = len(self.urls) * len(self.hosts)
        self.output.write_log(
            '%i hosts %i urls loaded, %i urls to scan' % (hosts_count, urls_count, full_urls_count),
            logging.INFO)

        # Check threds count vs hosts count
        if self.args.threads > hosts_count:
            self.output.write_log('Too many threads! Fixing threads count to %i' % hosts_count, logging.WARNING)
            self.threads_count = hosts_count
        else:
            self.threads_count = self.args.threads

        # Output urls count
        self.output.args.urls_count = full_urls_count

        # Queue and workers
        self.hosts_queue = JoinableQueue()
        self.workers = []

    def _init_scan_options(self):
        # Session
        self.session = session()
        self.session.timeout = self.args.timeout
        self.session.verify = False

        # TODO: debug and check
        # self.session.mount("http://", HTTPAdapter(max_retries=self.args.max_retries))
        # self.session.mount("https://", HTTPAdapter(max_retries=self.args.max_retries))
        # Max retries
        DEFAULT_RETRIES = self.args.max_retries

        # TOR
        if self.args.tor:
            self.output.write_log("TOR usage detected. Making some checks.", logging.INFO)
            self.session.proxies = {
                'http': 'socks5://127.0.0.1:9050',
                'https': 'socks5://127.0.0.1:9050'
            }

            url = 'http://ifconfig.me/ip'
            real_ip, tor_ip = None, None

            # Ger real IP address
            try:
                real_ip = get(url).text.strip()
            except Exception as exception:
                self.output.print_and_log("Couldn't get real IP address. Check yout internet connection.", logging.ERROR)
                self.output.write_log(str(exception), logging.ERROR)
                exit(-1)

            # Get TOR IP address
            try:
                tor_ip = self.session.get(url).text.strip()
            except Exception as exception:
                self.output.print_and_log("TOR socks proxy doesn't seem to be working.", logging.ERROR)
                self.output.write_log(str(exception), logging.ERROR)
                exit(-1)

            # Show IP addresses
            self.output.print_and_log('Real IP: %s TOR IP: %s' % (real_ip, tor_ip), logging.INFO)
            if real_ip == tor_ip:
                self.output.print_and_log("TOR doesn't work! Stop to be secure.", logging.ERROR)
                exit(-1)

        # Proxy
        if self.args.proxy is not None:
            self.session.proxies = {"https": self.args.proxy,
                                    "http": self.args.proxy}

        # Auth
        if self.args.auth is not None:
            items = self.args.auth.split(':')
            self.session.auth = (items[0], items[1])

        # Cookies
        if self.args.cookies is not None:
            self.session.cookies = Cookies.from_request(self.args.cookies)

        # Cookies from file
        if self.args.load_cookies is not None:
            if not path.exists(self.args.load_cookies) or not path.isfile(self.args.load_cookies):
                self.output.print_and_log('Could not find cookie file: %s' % self.args.load_cookies, logging.ERROR)
                exit(-1)

            cj = MozillaCookieJar(self.args.load_cookies)
            cj.load()
            self.session.cookies = cj

        # User-Agent
        self.ua = UserAgent() if self.args.random_agent else None

    def _host_to_url(self, host):
        return 'https://%s' % host if ':443' in host else 'http://%s' % host if not host.lower().startswith(
            'http') else host

    def _file_to_list(self, filename, dedup=False):
        """
        Get list from file
        :param filename: file to read
        :return: list of lines
        """
        if not path.exists(filename) or not path.isfile(filename):
            self.output.print_and_log('File %s not found' % filename, logging.ERROR)
            exit(-1)

        # Preparing lines list
        lines = filter(lambda x: x is not None and len(x) > 0, open(filename).read().split('\n'))
        return deduplicate(lines) if dedup else lines

    def worker(self, num):
        self.output.write_log('Worker %i started.' % num)
        while not self.hosts_queue.empty():
            host = self.hosts_queue.get()
            try:
                self._scan_host(num, host)
            finally:
                self.output.write_log('Worker %i finished.' % num)
                self.hosts_queue.task_done()

    def _head_available(self, host):
        # Trying to use OPTIONS request
        response = self.session.options(host)
        o = response.headers['allow'] if 'allow' in response.headers else None

        # Determine if HEAD requests is allowed
        if o is not None:
            head_available = False if o.find('HEAD') == -1 else True
        else:
            head_available = False if self.session.head(host).status_code == 405 else True

        return head_available

    def _icmp_ping(self, host, timeout=10):
        # TODO: check and debug
        response = sr1(IP(dst=host) / ICMP(), timeout=timeout)
        return response is not None

    def _syn_scan(self, host, ports=[80]):
        # TODO: check and debug
        a, u = sr(IP(dst=host) / TCP(sport=RandShort(), dport=ports, flags="S"), timeout=0.1)
        # ports =
        a.summary(
            # apply the filter function to each packet (i.e. decide whether
            # it will be displayed or not)
            lfilter=lambda (s, r): r.sprintf("%TCP.flags%") == "SA",
            # function to apply to each packet
            prn=lambda (s, r): r.sprintf("%TCP.sport% is open"
                                         " (%TCP.flags%)")
        )

        return []

    def _scan_host(self, worker_id, host):
        # TODO: add ICMP ping check
        # TODO: add SYN check and scan
        head_available = False
        if self.args.head:
            head_available = self._head_available(host)
            if head_available:
                self.output.write_log('HEAD is supported for %s' % host)

        errors_count = 0
        for url in self.urls:
            full_url = urljoin(self._host_to_url(host), url)
            r = self._scan_url(worker_id, full_url, head_available)
            if r is None:
                errors_count += 1

            if self.args.skip is not None and errors_count == self.args.skip:
                return

    def _scan_url(self, worker_id, url, use_head=False):
        """
        Scan specified URL with HTTP GET request
        :param url: url to scan
        :return: HTTP response
        """
        self.output.write_log('Scanning %s' % url, logging.DEBUG)

        # Fill UserAgent in headers
        headers = {}
        if self.args.user_agent is not None:
            headers['User-agent'] = self.args.user_agent
        elif self.args.random_agent:
            headers['User-agent'] = self.ua.random

        # Fill Referer in headers
        if self.args.referer is not None:
            headers['Referer'] = self.args.referer

        # Query URL and handle exceptions
        response, exception = None, None
        try:
            # TODO: add support for user:password in URL
            if use_head:
                response = self.session.head(url, headers=headers, allow_redirects=self.args.allow_redirects)
            else:
                response = self.session.get(url, headers=headers, allow_redirects=self.args.allow_redirects)
        except ConnectionError as exception:
            self.output.write_log('Connection error while quering %s' % url, logging.ERROR)
            return None
        except HTTPError as exception:
            self.output.write_log('HTTP error while quering %s' % url, logging.ERROR)
            return None
        except Timeout as exception:
            self.output.write_log('Timeout while quering %s' % url, logging.ERROR)
            return None
        except TooManyRedirects as exception:
            self.output.write_log('Too many redirects while quering %s' % url, logging.ERROR)
            return None
        except Exception as exception:
            self.output.write_log('Unknown exception while quering %s' % url, logging.ERROR)
            return None

        self.output.write(worker_id, url, response, exception)
        return response

    def signal_handler(self):
        """
        Signal hdndler
        :return:
        """
        self.output.write_log('Signal caught. Stopping...', logging.WARNING)
        print('Signal caught. Stopping...')
        self.stop()
        exit(signal.SIGINT)

    def start(self):
        """
        Start mulithreaded scan
        :return:
        """
        # Set signal handler
        gevent.signal(signal.SIGTERM, self.signal_handler)
        gevent.signal(signal.SIGINT, self.signal_handler)
        gevent.signal(signal.SIGQUIT, self.signal_handler)

        # Start workers
        self.workers = [spawn(self.worker, i) for i in range(self.threads_count)]

        # Fill and join queue
        [self.hosts_queue.put(host) for host in self.hosts]
        self.hosts_queue.join()

    def stop(self):
        """
        Stop scan
        :return:
        """
        # TODO: add saving status via pickle
        gevent.killall(self.workers)


def http_scan(args):
    start = strnow()
    HttpScanner(args).start()
    print(Fore.RESET + 'Statisitcs:\nScan started %s\nScan finished %s' % (start, strnow()))


def main():
    parser = ArgumentParser('httpscan', description='Multithreaded HTTP scanner',
                            formatter_class=ArgumentDefaultsHelpFormatter, fromfile_prefix_chars='@')

    # main options
    parser.add_argument('hosts', help='hosts file')
    parser.add_argument('urls', help='urls file')

    # scan options
    group = parser.add_argument_group('Scan options')
    group.add_argument('-t', '--timeout', type=int, default=10, help='scan timeout')
    group.add_argument('-T', '--threads', type=int, default=5, help='threads count')
    group.add_argument('-m', '--max-retries', type=int, default=3, help='Max retries for the request')
    group.add_argument('-p', '--proxy', help='HTTP/SOCKS proxy to use (http://user:pass@127.0.0.1:8080)')
    group.add_argument('-a', '--auth', help='HTTP Auth user:password')
    group.add_argument('-c', '--cookies', help='cookies to send during scan')
    group.add_argument('-C', '--load-cookies', help='load cookies from specified file')
    group.add_argument('-u', '--user-agent', help='User-Agent to use')
    group.add_argument('-U', '--random-agent', action='store_true', help='use random User-Agent')
    group.add_argument('-d', '--dump', help='save found files to directory')
    group.add_argument('-R', '--referer', help='referer URL')
    group.add_argument('-s', '--skip', type=int, help='skip host if errors count reached value')
    group.add_argument('-r', '--allow-redirects', action='store_true', help='follow redirects')
    group.add_argument('-H', '--head', action='store_true', help='try to use HEAD request if possible')
    group.add_argument('--tor', action='store_true', help='Use TOR as proxy')
    # group.add_argument('-i', '--ping', action='store_true', help='use ICMP ping request to detect if host available')
    # group.add_argument('-S', '--syn', action='store_true', help='use SYN scan to check if port is available')
    # group.add_argument('-P', '--port',  help='ports to scan')

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
    group.add_argument('-oD', '--output-database',
                       help='output results to database via SQLAlchemy (postgres://postgres@localhost/name)')

    # Debug and logging options
    group = parser.add_argument_group('Debug output and logging options')
    group.add_argument('-D', '--debug', action='store_true', help='write program debug output to file')
    group.add_argument('-L', '--log-file', help='debug log path')

    # Parse args and start scanning
    args = parser.parse_args()
    http_scan(args)


if __name__ == '__main__':
    main()