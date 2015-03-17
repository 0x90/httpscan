#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
# Simple Multithreaded HTTP scanner.
# Feel free to contribute.
#
# Usage example:
#
#   ./httpscan.py hosts.txt urls.txt -T 10 -A 200 -oC test.csv -r -U -L scan.log --tor
#
__author__ = '090h'
__license__ = 'GPL'
__version__ = '0.3'

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
from requests import ConnectionError, HTTPError, Timeout, TooManyRedirects
from requests import packages, get
from cookies import Cookies
from fake_useragent import UserAgent
from colorama import init, Fore
from gevent.lock import RLock
from gevent.pool import Pool
from gevent import spawn
import gevent
import requesocks


def strnow():
    """
    Current datetime
    :return: string for current datetime
    """
    return datetime.now().strftime('%d.%m.%Y %H:%M:%S')


class Output(object):
    def __init__(self, args):
        self.args = args
        self.lock = RLock()

        # Colorama init
        init()

        # Initialise logging
        self._init_logger()
        self._init_requests_output()

        # Initialise output
        self._init_csv()
        self._init_json()
        self._init_dump()

        # Initialise percentage
        self.urls_scanned = 0

    def _init_logger(self):
        """
        Init logger
        :return: logger
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
        Init requests output
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
            self.csv = writer(open(self.args.output_csv, 'wb'), delimiter=';', quoting=QUOTE_ALL)
            self.csv.writerow(['url', 'status', 'length', 'headers'])

    def _init_json(self):
        """
        Initialise JSON output
        :return:
        """
        self.json = None if self.args.output_json is None else io.open(self.args.output_json, 'w', encoding='utf-8')

    def _init_dump(self):
        """
        Initialise dump folder
        :return:
        """
        self.dump = path.abspath(self.args.dump) if self.args.dump is not None else None
        if self.dump is not None and not path.exists(self.dump):
            makedirs(self.dump)

    def _parse_response(self, url, response):
        """
        Parse url and response to dictionary
        :param url:
        :param response:
        :return:
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

    def write(self, url, response, exception):
        """
        Write url and response to output asynchronously
        :param url:
        :param response:
        :return:
        """
        spawn(self.write_func, url, response, exception)

    def write_func(self, url, response, exception):
        """
        Write url and response to output synchronously
        :param url:
        :param response:
        :return:
        """
        # Acquire lock
        self.lock.acquire()
        parsed = self._parse_response(url, response)

        # Calculate progreess
        self.urls_scanned += 1
        percentage = '{percent:.2%}'.format(percent=float(self.urls_scanned) / self.args.urls_count)
        # TODO: add detailed stats

        # Print colored output
        out = '[%s] [%s]\t%s -> %i' % (strnow(), percentage, parsed['url'], parsed['status'])
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
            if exception is None:
                self.logger.info('%s %s %i' % (url, parsed['status'], parsed['length']))
            else:
                self.logger.info('%s %s %i %s' % (url, parsed['status'], parsed['length'], str(exception)))

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
            if self.dump is not None and exception is None:
                self.write_dump(url, response)

        # Realse lock
        self.lock.release()

    def write_dump(self, url, response):
        """
        Write dump
        :param url:
        :param response:
        :return:
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

    def write_log(self, msg, loglevel=logging.INFO):
        """
        Write log
        :param msg:
        :param loglevel:
        :return:
        """
        if self.logger is None:
            return

        self.lock.acquire()
        if loglevel == logging.INFO:
            self.logger.info(msg)
        elif loglevel == logging.DEBUG:
            self.logger.debug(msg)
        elif loglevel == logging.ERROR:
            self.logger.error(msg)
        elif loglevel == logging.WARNING:
            self.logger.warning(msg)

        self.lock.release()


class HttpScanner(object):
    def __init__(self, args):
        """
        Initialise HTTP scanner
        :param args:
        :return:
        """
        self.args = args

        # Session
        self.session = requesocks.session()
        self.session.timeout = self.args.timeout
        self.session.verify = False

        # TOR
        if args.tor:
            print("TOR usage detected. Making some checks.")
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
                print("Couldn't get real IP address. Check yout internet connection.")
                exit(01)

            # Ger TOR IP address
            try:
                tor_ip = self.session.get(url).text.strip()
            except Exception as exception:
                print("TOR socks proxy doesn't seem to be working.")
                exit(-1)

            # Show IP addresses
            print('Real IP: %s TOR IP: %s' % (real_ip, tor_ip))
            if real_ip == tor_ip:
                print("TOR doesn't work! Stop to be secure.")
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
                self.output.write_log('Could not find cookie file: %s' % self.args.load_cookies, logging.ERROR)
                exit(-1)

            cj = MozillaCookieJar(self.args.load_cookies)
            cj.load()
            self.session.cookies = cj

        # User-Agent
        self.ua = UserAgent() if self.args.random_agent else None

        # Reading files
        print("Reading files.")
        hosts = self.__file_to_list(args.hosts)
        urls = self.__file_to_list(args.urls)

        # Generating full url list
        print("Generating deduplicated url list. Wait a moment...")
        self.urls = []
        for host in hosts:
            host = 'https://%s' % host if ':443' in host else 'http://%s' % host if not host.lower().startswith(
                'http') else host

            for url in urls:
                full_url = urljoin(host, url)
                if full_url not in self.urls:
                    self.urls.append(full_url)
        urls_count = len(self.urls)
        print('%i hosts %i urls loaded, %i urls to scan' % (len(hosts), len(urls), urls_count))

        # Output
        a = args
        a.urls_count = urls_count
        self.output = Output(a)

        # Pool
        if self.args.threads > urls_count:
            print('Too many threads! Fixing threads count to %i' % urls_count)
            self.pool = Pool(urls_count)
        else:
            self.pool = Pool(self.args.threads)

    def __file_to_list(self, filename):
        """
        Get list from file
        :param filename: file to read
        :return: list of lines
        """
        if not path.exists(filename) or not path.isfile(filename):
            self.output.write_log('File %s not found' % filename, logging.ERROR)
            exit(-1)
        return filter(lambda x: x is not None and len(x) > 0, open(filename).read().split('\n'))

    def scan(self, url):
        """
        Scan specified URL with HTTP GET request
        :param url: url to scan
        :return: HTTP response
        """
        self.output.write_log('Scanning %s' % url, logging.DEBUG)

        # Fill headers
        headers = {}
        if self.args.user_agent is not None:
            headers = {'User-agent': self.args.user_agent}
        if self.args.random_agent:
            headers = {'User-agent': self.ua.random}

        # Query URL and handle exceptions
        response = None
        exception = None
        try:
            # TODO: add support for user:password in URL
            response = self.session.get(url, headers=headers, allow_redirects=self.args.allow_redirects)
        except ConnectionError as exception:
            self.output.write_log('Connection error while quering %s' % url, logging.ERROR)
        except HTTPError as exception:
            self.output.write_log('HTTP error while quering %s' % url, logging.ERROR)
        except Timeout as exception:
            self.output.write_log('Timeout while quering %s' % url, logging.ERROR)
        except TooManyRedirects as exception:
            self.output.write_log('Too many redirects while quering %s' % url, logging.ERROR)
        except Exception as exception:
            self.output.write_log('Unknown exception while quering %s' % url, logging.ERROR)

        self.output.write(url, response, exception)

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

        # Start scanning
        self.pool.map(self.scan, self.urls)

    def stop(self):
        """
        Stop scan
        :return:
        """
        self.pool.kill(block=True, timeout=4)
        # TODO: add saving status via pickle


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
    group.add_argument('-r', '--allow-redirects', action='store_true', help='follow redirects')
    group.add_argument('-p', '--proxy', help='HTTP/SOCKS proxy to use (http://user:pass@127.0.0.1:8080)')
    group.add_argument('--tor', action='store_true', help='Use TOR as proxy')
    group.add_argument('-a', '--auth', help='HTTP Auth user:password')
    group.add_argument('-c', '--cookies', help='cookies to send during scan')
    group.add_argument('-C', '--load-cookies', help='load cookies from specified file')
    group.add_argument('-u', '--user-agent', help='User-Agent to use')
    group.add_argument('-U', '--random-agent', action='store_true', help='use random User-Agent')
    group.add_argument('-d', '--dump', help='save found files to directory')
    # TODO: add Referer argument
    # group.add_argument('-R', '--referer', help='referer url')

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
    # group.add_argument('-P', '--progress-bar', action='store_true', help='show scanning progress')

    # Debug and logging options
    group = parser.add_argument_group('Debug output and logging options')
    group.add_argument('-D', '--debug', action='store_true', help='write program debug output to file')
    group.add_argument('-L', '--log-file', help='debug log path')

    # Parse args and start scanning
    args = parser.parse_args()
    http_scan(args)

if __name__ == '__main__':
    main()