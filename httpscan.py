#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
# Dummy Multithreaded HTTP scanner.
# Not properly tested and bugfixed.
# Feel free to contribute.
#
# Usage example:
# ./httpscan.py hosts.txt urls.txt -T 10 -A 200 -oC test.csv -r -R -D -L scan.log
#
__author__ = '090h'
__license__ = 'GPL'
__version__ = '0.3'


from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser
from sys import exit
from os import path, makedirs
from datetime import datetime
from urlparse import urlparse, urljoin
from csv import writer, QUOTE_ALL
from json import dumps
import cookielib
import httplib
import io
import logging
import signal

# External dependencied
from requests import ConnectionError, HTTPError, Timeout, TooManyRedirects
from requests import packages, get
from cookies import Cookies
from fake_useragent import UserAgent
from colorama import init, Fore, Back, Style
from gevent.lock import RLock
from gevent.pool import Pool
import gevent

# Check Python version
from platform import python_version
if python_version() == '2.7.9':
    print("Gevent doesn't work in proper way under Python 2.7.9")
    print("https://github.com/gevent/gevent/issues/477")
    exit(-1)

def strnow():
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

    def _init_logger(self):
        """ Init logger
        :return: logger
        """
        if self.args.log_file is not None:
            self.logger = logging.getLogger('httpscan_logger')
            self.logger.setLevel(logging.DEBUG if self.args.debug else logging.INFO)
            # handler = StreamHandler() if args.log_file is None else FileHandler(args.log_file)
            handler = logging.FileHandler(self.args.log_file)
            handler.setFormatter(
                logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%d.%m.%Y %H:%M:%S'))
            self.logger.addHandler(handler)
        else:
            self.logger = None

    def _init_requests_output(self):
        """ Init requests
        :return: None
        """
        if self.args.debug:
            # Enable requests lib debug output
            httplib.HTTPConnection.debuglevel = 5
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
        # CSV output
        if self.args.output_csv is None:
            self.csv = None
        else:
            self.csv = writer(open(self.args.output_csv, 'wb'), delimiter=';', quoting=QUOTE_ALL)
            self.csv.writerow(['url', 'status', 'length'])

    def _init_json(self):
        # JSON output
        self.json = None if self.args.output_json is None else io.open(self.args.output_json, 'w', encoding='utf-8')

    def _init_dump(self):
        # Dump to file
        self.dump = path.abspath(self.args.dump) if self.args.dump is not None else None

    def _parse_response(self, url, response):
        return {'url': url,
                'status': response.status_code,
                'length': int(response.headers['content-length']) if 'content-length' in response.headers else len(
                    response.text)}

    def write(self, url, response):
        gevent.spawn(self.write_func, url, response)

    def write_func(self, url, response):
        # TODO: add async logging for speed up
        self.lock.acquire()
        parsed = self._parse_response(url, response)

        # Print colored output
        if not self.args.progress_bar:
            if parsed['status'] == 200:
                print(Fore.GREEN + '[%s] %s -> %i' % (strnow(), parsed['url'], parsed['status']))
            elif 400 <= parsed['status'] < 500:
                print(Fore.RED + '[%s] %s -> %i' % (strnow(), parsed['url'], parsed['status']))
            else:
                print(Fore.YELLOW + '[%s] %s -> %i' % (strnow(), parsed['url'], parsed['status']))

        # Write to log file
        if self.logger is not None:
            self.logger.info('%s %s %i' % (url, response.status_code, len(response.text)))

        # Write to CSV file
        if self.csv is not None:
            self.csv.writerow([parsed['url'], parsed['status'], parsed['length']])

        # Write to JSON file
        if self.json is not None:
            self.json.write(unicode(dumps(parsed, ensure_ascii=False)))

        # Save contents to file
        if self.dump is not None:
            self.write_dump(url, response)

        # Realse lock
        self.lock.release()

    def write_dump(self, url, response):
        parsed = urlparse(url)
        host_folder = path.join(self.dump, parsed.netloc)
        p, f = path.split(parsed.path)
        folder = path.join(host_folder, p[1:])

        if not path.exists(folder):
            makedirs(folder)
        filename = path.join(folder, f)

        with open(filename, 'wb') as f:
            f.write(response.content)

    def write_log(self, msg, loglevel=logging.INFO):
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
        self.args = args
        self.output = Output(args)


        # Reading files
        hosts = self.__file_to_list(args.hosts)
        urls = self.__file_to_list(args.urls)

        # Generating full url list
        self.urls = []
        for host in hosts:
            host = 'https://%s' % host if ':443' in host else 'http://%s' % host if not host.lower().startswith(
                'http') else host

            for url in urls:
                full_url = urljoin(host, url)
                if full_url not in self.urls:
                    self.urls.append(full_url)

        print('%i hosts %i urls loaded, %i urls to scan' % (len(hosts), len(urls), len(self.urls)))

        # Pool
        if self.args.threads > len(self.urls):
            print('Too many threads! Fixing threads count to %i' % len(self.urls))
            self.pool = Pool(len(self.urls))
        else:
            self.pool = Pool(self.args.threads)

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
                self.output.write_log('Could not find cookie file: %s' % self.args.load_cookies, logging.ERROR)
                exit(-1)

            self.cookies = cookielib.MozillaCookieJar(self.args.load_cookies)
            self.cookies.load()

        # User-Agent
        self.ua = UserAgent() if self.args.random_agent else None

    def __file_to_list(self, filename):
        if not path.exists(filename) or not path.isfile(filename):
            self.output.write_log('File %s not found' % filename, logging.ERROR)
            exit(-1)
        return filter(lambda x: x is not None and len(x) > 0, open(filename).read().split('\n'))

    def scan(self, url):
        self.output.write_log('Scanning  %s' % url, logging.DEBUG)

        # Fill headers
        headers = {}
        if self.args.user_agent is not None:
            headers = {'User-agent': self.args.user_agent}
        if self.args.random_agent:
            headers = {'User-agent': self.ua.random}

        # Query URL and handle exceptions
        try:
            # TODO: add support for user:password in URL
            response = get(url, timeout=self.args.timeout, headers=headers, allow_redirects=self.args.allow_redirects,
                           verify=False, cookies=self.cookies, auth=self.auth)
        except ConnectionError:
            self.output.write_log('Connection error while quering %s' % url, logging.ERROR)
            return None
        except HTTPError:
            self.output.write_log('HTTP error while quering %s' % url, logging.ERROR)
            return None
        except Timeout:
            self.output.write_log('Timeout while quering %s' % url, logging.ERROR)
            return None
        except TooManyRedirects:
            self.output.write_log('Too many redirects while quering %s' % url, logging.ERROR)
            return None
        except Exception:
            self.output.write_log('Unknown exception while quering %s' % url, logging.ERROR)
            return None

        # Filter responses and save responses that are matching ignore, allow rules
        if (self.args.allow is None and self.args.ignore is None) or \
                (self.args.allow is not None and response.status_code in self.args.allow) or \
                (self.args.ignore is not None and response.status_code not in self.args.ignore):
            self.output.write(url, response)

    def signal_handler(self):

        pass

    def start(self):
        # Set SIGINT/SIGTERM handler
        gevent.signal(signal.SIGTERM, self.stop)
        gevent.signal(signal.SIGINT, self.stop)

        # Start scanning
        self.pool.map(self.scan, self.urls)

    def stop(self):
        self.output.write_log('Ctrl+C caught. Stopping...', logging.WARNING)
        # gevent.killall(workers)

        # TODO: add saving status via pickle
        pass


def http_scan(args):
    hs = HttpScanner(args)
    hs.start()
    start = datetime.now()

    print(Fore.RESET + Back.RESET + Style.RESET_ALL + 'Statisitcs:')
    print('Scan started %s' % start.strftime('%d.%m.%Y %H:%M:%S'))
    finish = datetime.now()
    print('Scan finished %s' % finish.strftime('%d.%m.%Y %H:%M:%S'))


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
    group.add_argument('-p', '--proxy', help='HTTP proxy to use (http://user:pass@127.0.0.1:8080)')
    group.add_argument('-a', '--auth', help='HTTP Auth user:password')
    group.add_argument('-c', '--cookies', help='cookies to send during scan')
    group.add_argument('-C', '--load-cookies', help='load cookies from specified file')
    group.add_argument('-u', '--user-agent', help='User-Agent to use')
    group.add_argument('-R', '--random-agent', action='store_true', help='use random User-Agent')
    group.add_argument('-d', '--dump', help='save found files to directory')
    # TODO: add Referer argument

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