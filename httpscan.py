#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
# Multithreaded asynchronous HTTP scanner.
# Feel free to contribute.
#
# Usage examples:
# ./httpscan.py hosts.txt urls.txt -T 10 -A 200 -r -U  -L scan.log --tor -oC test.csv -oD sqlite:///test.db
# ./httpscan.py hosts.txt urls.txt -T 10 -A 200 -r -U  -L scan.log --tor -oC test.csv -oD sqlite:///test.db --icmp --syn --ports 80 443 8000 8080
# ./httpscan.py @args.txt

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
monkey.patch_all(thread=False)

# Basic dependencies
from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser
from sys import exit
from os import path, makedirs, geteuid
from datetime import datetime
from urlparse import urlparse, urljoin, urlsplit
from csv import writer, QUOTE_ALL
from json import dumps
from cookielib import MozillaCookieJar
from httplib import HTTPConnection
import signal
import io

# External dependencies
from sqlalchemy_utils.functions import create_database, database_exists
from sqlalchemy import create_engine, Table, Column, Integer, String, MetaData
from requests import ConnectionError, HTTPError, Timeout, TooManyRedirects
# from requests.adapters import HTTPAdapter, DEFAULT_RETRIES
from requests import packages, get, adapters
from requesocks import session
from cookies import Cookies
from fake_useragent import UserAgent
from colorama import init, Fore
from humanize import naturalsize
from gevent.queue import JoinableQueue
from gevent.lock import RLock
from gevent import spawn
from pprint import pprint
import gevent
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.layers.inet import ICMP, TCP, IP
conf.verb = False


class helper(object):

    @staticmethod
    def str_now(fmt='%d.%m.%Y %H:%M:%S'):
        """
        Current datetime to string
        :param fmt: format string for output
        :return: string for current datetime
        """
        return datetime.now().strftime(fmt)

    @staticmethod
    def deduplicate(seq):
        """
        Deduplicate list
        :param seq: list to deduplicate
        :return: deduplicated list
        """
        seen = set()
        seen_add = seen.add
        return [x for x in seq if not (x in seen or seen_add(x))]

    @staticmethod
    def host_to_url(host):
        return 'https://%s' % host if ':443' in host else 'http://%s' % host if not host.lower().startswith(
            'http') else host

    @staticmethod
    def hosts_to_domain_dict(hosts):
        domains = [helper.url_to_domain(host) for host in hosts]
        return dict(map(lambda d: (helper.domain_to_ip(d), d), domains))

    @staticmethod
    def hosts_to_port_dict(hosts):
        ports_dict = {}
        for host, port in [helper.parse_url(host) for host in hosts]:
            if port in ports_dict:
                ports_dict[port].append(helper.url_to_ip(host))
            else:
                ports_dict[port] = [helper.url_to_ip(host)]

        return ports_dict

    @staticmethod
    def parse_url(url):
        parsed = urlsplit(url)
        return parsed[1].split(':')[0] if '://' in url else url, parsed.port

    @staticmethod
    def url_to_ip(url):
        return helper.domain_to_ip(helper.url_to_domain(url))

    @staticmethod
    def generate_url(host, port):
        prefix = 'https://' if port in [443, 8443] else 'http://'
        return '%s%s:%i' % (prefix, host, port)

    @staticmethod
    def url_to_domain(url):
        return urlsplit(url)[1].split(':')[0] if '://' in url else url
        # domain = urlparse.urlsplit(url)[1].split(':')[0]
        # if '://' not in url:
        # return url
        # else:
        #     return url.split('://')[1].split('/')[0]

    @staticmethod
    def domain_to_ip(domain):
        return socket.gethostbyname(domain)

    @staticmethod
    def domain_to_ip_list(domain):
        from dns import resolver
        answers = resolver.query(domain, 'A')
        return [rdata for rdata in answers]

    @staticmethod
    def ping_host(host, timeout=1):
        return sr1(IP(dst=host)/ICMP(), timeout=timeout) is not None

    @staticmethod
    def scan_host(host, port, timeout=0.5):
        return sr1(IP(dst=host)/TCP(sport=RandShort(), dport=port, flags="S"), timeout=timeout) is not None

    @staticmethod
    def scan_url(url, timeout=0.5):
        parsed = urlsplit(url)
        host = parsed[1].split(':')[0] if '://' in url else url
        return sr1(IP(dst=host)/TCP(sport=RandShort(), dport=parsed.port, flags="S"), timeout=timeout) is not None

    @staticmethod
    def icmp_scan(hosts, timeout=3, http_prefix=True):
        domains_dict = helper.hosts_to_domain_dict(hosts)
        ips = [ip for ip in domains_dict.keys()]
        a, u = sr(IP(dst=ips) / ICMP(), timeout=timeout, retry=3)
        # domain names without http prefix
        available = [domains_dict[rcv[IP].src] for snd, rcv in a]
        return filter(lambda d: helper.url_to_domain(d) in available, hosts) if http_prefix else available

    @staticmethod
    def syn_scan(hosts, ports=None, timeout=3, http_prefix=True):
        domains = helper.hosts_to_domain_dict(hosts)
        available = {}

        def parse_answered(answered):
            for snd, rcv in answered:
                if rcv[TCP].flags != 'SA':
                    continue

                if rcv[IP].src in available:
                    available[rcv[IP].src] = [rcv[TCP].sport]
                else:
                    available[rcv[IP].src].append(rcv[TCP].sport)

        if ports is None:
            ports_dict = helper.hosts_to_port_dict(hosts)
            for port in ports_dict.keys():
                a = sr(IP(dst=ports_dict[port])/TCP(sport=RandShort(), dport=port, flags="S"), timeout=timeout)[0]
                parse_answered(a)
        else:
            a = sr(IP(dst=[ip for ip in domains.keys()])/TCP(sport=RandShort(), dport=ports, flags="S"), timeout=timeout)[0]
            parse_answered(a)

        # return available host:ports dict
        if not http_prefix:
            return available

        # generate url list
        urls = []
        for ip in available.keys():
            urls.extend([helper.generate_url(domains[ip], port) for port in available[ip]])
        return urls


class HttpScannerOutput(object):
    def __init__(self, args):
        # TODO: make separate queues for fast logging
        self.args = args
        self.lock = RLock()

        # Colorama init
        init()
        # Initialise logging
        self._init_logger()
        # Initialise output
        self._init_output()
        # Stats
        self.urls_scanned = 0

    def _init_output(self):
        # Initialise output
        self._init_requests_output()
        self._init_csv()
        self._init_json()
        self._init_dump()
        self._init_db()

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

    def write(self, **kwargs):
        spawn(self.write_func, **kwargs)

    def write_func(self, **kwargs):
        # Acquire lock
        self.lock.acquire()

        # Output
        self._display_progress(**kwargs)
        self._write_log(**kwargs)

        # Check for exception
        if kwargs['exception'] is None:
            self._filter_and_write(**kwargs)

        # Realse lock
        self.lock.release()

    def _display_progress(self, **kwargs):
        # TODO: add detailed stats
        # Calculate progreess
        self.urls_scanned += 1
        percentage = '{percent:.2%}'.format(percent=float(self.urls_scanned) / self.args.urls_count)

        # Generate and print colored output
        out = '[%s] [worker:%02i] [%s]\t%s ->\tstatus:%i\t' % (
            helper.str_now(), kwargs['worker'], percentage, kwargs['url'], kwargs['status'])
        if kwargs['exception'] is not None:
            out += 'error: (%s)' % str(kwargs['exception'])
        else:
            out += 'length: %s' % naturalsize(int(kwargs['length']))
        if kwargs['status'] == 200:
            print(Fore.GREEN + out + Fore.RESET)
        elif 400 <= kwargs['status'] < 500 or kwargs['status'] == -1:
            print(Fore.RED + out + Fore.RESET)
        else:
            print(Fore.YELLOW + out + Fore.RESET)

    def _filter_and_write(self, **kwargs):
        # Filter responses and save responses that are matching ignore, allow rules
        if (self.args.allow is None and self.args.ignore is None) or \
                (self.args.allow is not None and kwargs['status'] in self.args.allow) or \
                (self.args.ignore is not None and kwargs['status'] not in self.args.ignore):
            self._write_csv(**kwargs)
            self._write_json(**kwargs)
            self._write_dump(**kwargs)
            self._write_db(**kwargs)

    def _kwargs_to_params(self, **kwargs):
        return {'url': kwargs['url'], 'status': kwargs['status'], 'length': kwargs['length'],
                'headers': str(kwargs['response'].headers)}

    def _write_log(self, **kwargs):
        # Write to log file
        if self.logger is None:
            return

        out = '[worker:%02i] %s %s %i' % (kwargs['worker'], kwargs['url'], kwargs['status'], kwargs['length'])
        if kwargs['exception'] is None:
            self.logger.info(out)
        else:
            self.logger.error("%s %s" % (out, str(kwargs['exception'])))

    def _write_csv(self, **kwargs):
        if self.csv is None:
            return

        self.csv.writerow([kwargs['url'], kwargs['status'], kwargs['length'], str(kwargs['response'].headers)])

    def _write_json(self, **kwargs):
        if self.json is None:
            return

        # TODO: bugfix appending json
        self.json.write(unicode(dumps(self._kwargs_to_params(kwargs), ensure_ascii=False)))

    def _write_dump(self, **kwargs):
        if kwargs['response'] is None or self.dump is None:
            return

        # Generate folder and file path
        parsed = urlparse(kwargs['url'])
        host_folder = path.join(self.dump, parsed.netloc)
        p, f = path.split(parsed.path)
        folder = path.join(host_folder, p[1:])
        if not path.exists(folder):
            makedirs(folder)
        filename = path.join(folder, f)

        # Get all content
        try:
            content = kwargs['response'].content
        except Exception as exception:
            self.write_log('Failed to get content for %s Exception: %s' % (kwargs['url'], str(exception)))
            return

        # Save contents to file
        with open(filename, 'wb') as f:
            f.write(content)

    def _write_db(self, **kwargs):
        if self.engine is None:
            return
        # TODO: check if url exists in table
        self.scan_table.insert()
        params = self._kwargs_to_params(kwargs)
        self.engine.execute(self.scan_table.insert().execution_options(autocommit=True), params)

    def write_log(self, msg, loglevel=logging.INFO):
        """
        Write message to log file
        :param msg:
        :param loglevel:
        :return: None
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

    def print_and_log(self, msg, loglevel=logging.INFO):
        # TODO: make separate logging
        print('[%s] %s' % (helper.str_now(), msg))
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
        self.hosts = self._file_to_list(args.hosts)
        if self.args.ports is None and not self.args.syn:
            new_hosts = []
            for host in self.hosts:
                for port in self.args.ports:
                    new_hosts.append(helper.generate_url(host, port))
            self.hosts = new_hosts
        self.urls = self._file_to_list(args.urls)

        # Queue and workers
        self.hosts_queue = JoinableQueue()
        self.workers = []

    def _file_to_list(self, filename, dedup=True):
        """
        Get list from file
        :param filename: file to read
        :return: list of lines
        """
        if not path.exists(filename) or not path.isfile(filename):
            self.output.print_and_log('File %s not found!' % filename, logging.ERROR)
            exit(-1)

        # Preparing lines list
        lines = filter(lambda line: line is not None and len(line) > 0, open(filename).read().split('\n'))
        if len(lines) == 0:
            self.output.print_and_log('File %s is empty!' % filename, logging.ERROR)
            exit(-1)

        return helper.deduplicate(lines) if dedup else lines

    def _init_scan_options(self):
        # Session
        self.session = session()
        self.session.timeout = self.args.timeout
        self.session.verify = False

        # TODO: debug and check
        # self.session.mount("http://", HTTPAdapter(max_retries=self.args.max_retries))
        # self.session.mount("https://", HTTPAdapter(max_retries=self.args.max_retries))
        # http://stackoverflow.com/questions/15431044/can-i-set-max-retries-for-requests-request
        # Max retries
        adapters.DEFAULT_RETRIES = self.args.max_retries

        # TOR
        if self.args.tor:
            self.output.write_log("TOR usage detected. Making some checks.")
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
                self.output.print_and_log("Couldn't get real IP address. Check yout internet connection.",
                                          logging.ERROR)
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
            self.output.print_and_log('Real IP: %s TOR IP: %s' % (real_ip, tor_ip))
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

    def worker(self, worker_id):
        self.output.write_log('Worker %i started.' % worker_id)
        while not self.hosts_queue.empty():
            host = self.hosts_queue.get()
            try:
                self.scan_host(worker_id, host)
            finally:
                self.output.write_log('Worker %i finished.' % worker_id)
                self.hosts_queue.task_done()

    def _head_available(self, host):
        """
        Determine if HEAD requests is allowed
        :param host:
        :return:
        """
        # Trying to use OPTIONS request
        try:
            response = self.session.options(host, headers=self._fill_headers())
            o = response.headers['allow'] if 'allow' in response.headers else None
            if o is not None and o.find('HEAD') != -1:
                return True
        except:
            # TODO: fix
            pass

        try:
            return False if self.session.head(host, headers=self._fill_headers()).status_code == 405 else True
        except:
            # TODO: fix
            return False

    def scan_host(self, worker_id, host):
        # Check for HEAD
        host_url = helper.host_to_url(host)
        head_available = False
        if self.args.head:
            head_available = self._head_available(host)
            if head_available:
                self.output.write_log('HEAD is supported for %s' % host)

        errors_count, urls_scanned = 0, 0
        for url in self.urls:
            full_url = urljoin(host_url, url)
            r = self.scan_url(full_url, head_available)
            urls_scanned += 1

            # Output
            r['worker'] = worker_id
            self.output.write(**r)
            if r['exception'] is not None:
                errors_count += 1

            # Skip host on errors
            if self.args.skip is not None and errors_count == self.args.skip:
                self.output.write_log('Errors limit reached on %s Skipping other urls.' % host, logging.WARNING)
                self.output.urls_scanned += len(self.urls) - urls_scanned
                return

    def _fill_headers(self):
        # Fill UserAgent in headers
        headers = {}
        if self.args.user_agent is not None:
            headers['User-agent'] = self.args.user_agent
        elif self.args.random_agent:
            headers['User-agent'] = self.ua.random

        # Fill Referer in headers
        if self.args.referer is not None:
            headers['Referer'] = self.args.referer

        return headers

    def _parse_response(self, url, response, exception):
        res = {'url': url,
               'response': response,
               'exception': exception}

        if response is None or exception is not None:
            res.update({
                'status': -1,
                'length': -1,
            })
            return res

        try:
            length = int(response.headers['content-length']) if 'content-length' in response.headers else len(
                response.text)
        except Exception as exception:
            self.output.write_log(
                "Exception while getting content length for URL: %s Exception: %s" % (url, str(exception)),
                logging.ERROR)
            length = 0

        res.update({
            'status': response.status_code,
            'length': length,
        })
        return res

    def scan_url(self, url, use_head=False):
        self.output.write_log('Scanning %s' % url, logging.DEBUG)

        # Query URL and handle exceptions
        response, exception = None, None
        method = 'HEAD' if use_head else 'GET'
        try:
            # TODO: add support for user:password in URL
            response = self.session.request(method, url, headers=self._fill_headers(),
                                            allow_redirects=self.args.allow_redirects)
        except ConnectionError as ex:
            self.output.write_log('Connection error while quering %s' % url, logging.ERROR)
            exception = ex
        except HTTPError as ex:
            self.output.write_log('HTTP error while quering %s' % url, logging.ERROR)
            exception = ex
        except Timeout as ex:
            self.output.write_log('Timeout while quering %s' % url, logging.ERROR)
            exception = ex
        except TooManyRedirects as ex:
            self.output.write_log('Too many redirects while quering %s' % url, logging.ERROR)
            exception = ex
        except Exception as ex:
            self.output.write_log('Unknown exception while quering %s' % url, logging.ERROR)
            exception = ex

        return self._parse_response(url, response, exception)

    def signal_handler(self):
        """
        Signal hdndler
        :return:
        """
        # TODO: add saving status via pickle
        self.output.print_and_log('Signal caught. Stopping...', logging.WARNING)
        self.stop()
        exit(signal.SIGINT)

    def _calc_urls(self):
        # Calculations
        self.urls_count = len(self.urls)
        self.hosts_count = len(self.hosts)
        self.full_urls_count = len(self.urls) * len(self.hosts)

    def start(self):
        """
        Start mulithreaded scan
        :return:
        """
        # Set signal handler
        gevent.signal(signal.SIGTERM, self.signal_handler)
        gevent.signal(signal.SIGINT, self.signal_handler)
        gevent.signal(signal.SIGQUIT, self.signal_handler)

        self._calc_urls()
        self.output.print_and_log(
            'Loaded %i hosts %i urls. %i full urls to scan' % (self.hosts_count, self.urls_count, self.full_urls_count))

        # ICMP scan
        if self.args.icmp:
            if geteuid() != 0:
                self.output.print_and_log('To use ICMP scan option you must run as root. Skipping ICMP scan', logging.WARNING)
            else:
                self.output.print_and_log('Starting ICMP scan.')
                self.hosts = helper.icmp_scan(self.hosts, self.args.timeout)
                self._calc_urls()
                self.output.print_and_log('After ICMP scan %i hosts %i urls loaded, %i urls to scan' %
                                          (self.hosts_count, self.urls_count, self.full_urls_count))

        # SYN scan
        if self.args.syn:
            if self.args.tor or self.args.proxy is not None:
                self.output.print_and_log('SYN scan via tor or proxy is impossible!', logging.WARNING)
                self.output.print_and_log('Stopping to prevent deanonymization!', logging.WARNING)
                exit(-1)

            if geteuid() != 0:
                self.output.print_and_log('To use SYN scan option you must run as root. Skipping SYN scan', logging.WARNING)
            else:
                self.output.print_and_log('Starting SYN scan.')
                self.hosts = helper.syn_scan(self.hosts, self.args.ports, self.args.timeout)
                self._calc_urls()
                self.output.print_and_log('After SYN scan %i hosts %i urls loaded, %i urls to scan' %
                                          (self.hosts_count, self.urls_count, self.full_urls_count))

        # Check threds count vs hosts count
        if self.args.threads > self.hosts_count:
            self.output.write_log('Too many threads! Fixing threads count to %i' % self.hosts_count, logging.WARNING)
            threads_count = self.hosts_count
        else:
            threads_count = self.args.threads

        # Output urls count
        self.output.args.urls_count = self.full_urls_count

        # Start workers
        self.workers = [spawn(self.worker, i) for i in range(threads_count)]

        # Fill and join queue
        [self.hosts_queue.put(host) for host in self.hosts]
        self.hosts_queue.join()

    def stop(self):
        """
        Stop scan
        :return:
        """
        # TODO: stop correctly
        gevent.killall(self.workers)


def http_scan(args):
    start = helper.str_now()
    HttpScanner(args).start()
    print(Fore.RESET + 'Statisitcs:\nScan started %s\nScan finished %s' % (start, helper.str_now()))


def main():
    parser = ArgumentParser('httpscan', description='Multithreaded HTTP scanner',
                            formatter_class=ArgumentDefaultsHelpFormatter, fromfile_prefix_chars='@')

    # Main options
    parser.add_argument('hosts', help='hosts file')
    parser.add_argument('urls', help='urls file')

    # Scan options
    group = parser.add_argument_group('Scan options')
    group.add_argument('-t', '--timeout', type=int, default=5, help='scan timeout')
    group.add_argument('-T', '--threads', type=int, default=5, help='threads count')
    group.add_argument('-m', '--max-retries', type=int, default=3, help='Max retries for the request')
    group.add_argument('-p', '--proxy', help='HTTP/SOCKS proxy to use (http://user:pass@127.0.0.1:8080)')
    group.add_argument('-d', '--dump', help='save found files to directory')
    group.add_argument('-s', '--skip', type=int, help='skip host if errors count reached value')
    group.add_argument('-r', '--allow-redirects', action='store_true', help='follow redirects')
    group.add_argument('-H', '--head', action='store_true', help='try to use HEAD request if possible')
    group.add_argument('--tor', action='store_true', help='Use TOR as proxy')

    # HTTP options
    group = parser.add_argument_group('HTTP options')
    group.add_argument('-a', '--auth', help='HTTP Auth user:password')
    group.add_argument('-c', '--cookies', help='cookies to send during scan')
    group.add_argument('-C', '--load-cookies', help='load cookies from specified file')
    group.add_argument('-u', '--user-agent', help='User-Agent to use')
    group.add_argument('-U', '--random-agent', action='store_true', help='use random User-Agent')
    group.add_argument('-R', '--referer', help='referer URL')

    group = parser.add_argument_group('Advanced scan options')
    group.add_argument('-i', '--icmp', action='store_true',
                       help='use ICMP ping request to detect if host available')
    group.add_argument('-S', '--syn', action='store_true', help='use SYN scan to check if port is available')
    group.add_argument('-P', '--ports', nargs='+', type=int, help='ports to scan')

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
    group = parser.add_argument_group('Debug and logging options')
    group.add_argument('-D', '--debug', action='store_true', help='write program debug output to file')
    group.add_argument('-L', '--log-file', help='debug log path')

    # Parse args and start scanning
    http_scan(parser.parse_args())


if __name__ == '__main__':
    main()