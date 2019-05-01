import requests
import sys
import platform
from time import gmtime, strftime
from helpers.colors import bcolors
from wappalyzer.analyzer import getSimple, getDetail
import helpers.ascii_art as art
from spider.crawler import Crawler
from spider.adminpage import search_admin_pages
import ssl
import OpenSSL
import socket
import re
from datetime import datetime
from helpers.helpers import strip_url


class Configer:
    """Get all possible info about app configuration from it's URL"""
    def __init__(self, url, settings):
        self.url = url
        self.settings = settings
        self.local = settings['local']                   # check if development mode
        self.r = self.get_headers()          # http request header
        self.detected = getSimple(self.url)  # web-app confifuration
        self.cookie = self.get_cookie()
        self.date = self.get_date()
        self.encoding = bcolors.WARNING + self.r.encoding
        self.server = self.get_server()
        self.compression = self.get_compression()
        self.os = self.get_os()
        self.programming_lang = self.get_language()
        self.certificate = self.check_ssl(self.url)
        self.pages = []
        self.adminpages = []
        self.pagelimit = settings["page_limit"]

    def get_headers(self):
        """Get headers from request and handle possible errors"""
        try:
            r = requests.get(self.url, timeout=3, verify=True)
            r.raise_for_status()
        except requests.exceptions.HTTPError as errh:
            print("Http Error:", errh)
            sys.exit(1)
        except requests.exceptions.ConnectionError as errc:
            print("Error Connecting:", errc)
            sys.exit(1)
        except requests.exceptions.Timeout as errt:
            print("Timeout Error:", errt)
            sys.exit(1)
        except requests.exceptions.RequestException as err:
            print("OOps: Something Else", err)
            sys.exit(1)
        return r


    def get_compression(self):
        try:
            return bcolors.OKGREEN + self.r.headers['Content-Encoding'] + bcolors.RESET
        except:
            return bcolors.FAIL + "hidden"


    def get_date(self):
        """Return current GMT from response header or generate it  manually"""
        try:
            return bcolors.OKGREEN + self.r.headers['Date']
        except:
            return bcolors.OKGREEN + strftime("%a, %d %b %Y %X GMT", gmtime())


    def output_configuration(self):
        """Print human-readable results of analysis"""
        art.spin_dash(2)
        print(bcolors.OKGREEN + "###########################################################################")
        print(bcolors.OKGREEN + "###########################################################################")
        print()
        art.owasp_scan_header()
        print(bcolors.OKGREEN + "###########################################################################")
        print(bcolors.OKGREEN + "###########################################################################")
        print()
        print(bcolors.OKGREEN + "Connecting to " + bcolors.OKBLUE + self.url  + "..." + bcolors.OKGREEN)
        art.update_progress(2)
        print(bcolors.OKGREEN + "---------------------------------------------------------------------------")
        print(bcolors.OKGREEN + "--------------------------CONFIGER SCAN SEARCH-----------------------------")
        print(bcolors.OKGREEN + "---------------------------------------------------------------------------")
        print(bcolors.OKGREEN + f"GET REQUEST with cookie: {self.cookie}")
        print(bcolors.OKGREEN + f"Time of connection: {self.date}")
        print(bcolors.OKGREEN + f"Certificate: {self.certificate}")
        print(bcolors.OKGREEN + f"Server: {self.server}")
        print(bcolors.OKGREEN + f"Operating system: {self.os}")
        print(bcolors.OKGREEN + f"Encoding: {self.encoding}")
        print(bcolors.OKGREEN + f"Programming language: {self.programming_lang}")
        print(bcolors.OKGREEN + f"Compression: {self.compression}")
        print(bcolors.OKGREEN + "------------------Search for possible admin/login pages--------------------")
        self.adminpages = search_admin_pages(self.url, progress=0, ext='php' if 'PHP' in self.programming_lang else 'a',
        									 wordlist_file="spider/admin_login.txt")
        print(bcolors.OKGREEN + f"admin/dashboard pages found: {len(self.adminpages)}")
        print(bcolors.OKGREEN + "-----------------------Search for all website pages------------------------")
        self.pages = self.get_pages(self.url)
        print(bcolors.OKGREEN + f"Webpages found: {len(self.pages)}")
        print(bcolors.OKGREEN + "---------------------------------------------------------------------------")
        print(bcolors.OKGREEN + "-----------------------------CONFIGER FINISHED-----------------------------")
        print(bcolors.OKGREEN + "---------------------------------------------------------------------------")
        print(bcolors.RESET)


    def get_server(self):
        """Try to get server type from header,
        highlight 'proxy-like' server name with orange
        """
        try:
            return bcolors.FAIL + self.detected['web-servers'] + bcolors.RESET
        except:
            try:
                return bcolors.WARNING + self.r.headers['Server'] + bcolors.RESET
            except:
                return bcolors.CYAN + 'hidden' + bcolors.RESET


    def get_os(self):
        if not self.local:
            try:
                return bcolors.FAIL + self.detected['operating-systems'] + bcolors.RESET
            except:
                return bcolors.CYAN + 'hidden' + bcolors.RESET
        else:
            return bcolors.WANING + platform.platform() + bcolors.RESET + bcolors.HEADER + ' [CURRENT PC]' + bcolors.RESET


    def get_cookie(self):
        try:
            return bcolors.FAIL + self.r.headers['Set-Cookie'] + bcolors.RESET
        except KeyError:
            return bcolors.CYAN + "hidden" + bcolors.RESET


    def get_language(self):
        """Try to get programming language from header"""
        try:
            # 1st try 
            return bcolors.FAIL + self.detected['programming-languages'] + bcolors.RESET
        except KeyError:
            try:
                # 2nd try
                return bcolors.FAIL + self.r.headers['X-Powered-By'] + bcolors.RESET
            except KeyError:
                # TODO: https://www.owasp.org/index.php/Testing_for_HTTP_Parameter_pollution_(OTG-INPVAL-004)
                return bcolors.CYAN + 'hidden' + bcolors.RESET


    def get_pages(self, url, no_verbose=False):
        """Return list of all webpages"""
        crawler = Crawler(url, no_verbose, limit=self.pagelimit)
        return crawler.start()
    

    def check_ssl(self, url):
        """TODO"""
        hostname = strip_url(url)
        port = 443
        try:
            cert = ssl.get_server_certificate((hostname, port))
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            date_until = str(datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ'))
            return '\033[1;36mvalid until ' + date_until
        except ssl.SSLError as e:
            print(e)
            return bcolors.FAIL + "certificate not found"
