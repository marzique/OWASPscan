"""TODO"""
import requests
import sys
import platform
from time import gmtime, strftime
from helpers.colors import bcolors
from wappalyzer.analyzer import getSimple, getDetail
import helpers.ascii_art as art
from checkssl import check_site
from tqdm import tqdm
from spider.crawler import Crawler
from spider.adminpage import search_admin_pages


class Configer:
    """Get all possible info about app configuration from it's URL"""
    def __init__(self, url, local=False):
        self.url = url
        self.local = local                   # check if development mode
        self.r = self.get_headers()          # http request header
        self.detected = getSimple(self.url)  # web-app confifuration
        self.cookie = self.get_cookie()
        self.date = self.get_date()
        self.encoding = bcolors.CYAN + self.r.encoding
        self.server = self.get_server()
        self.compression = self.get_compression()
        self.os = self.get_os()
        self.programming_lang = self.get_language()
        self.certificate = check_site(self.url)
        self.pages = []
        self.adminpages = []

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
            return bcolors.CYAN + self.r.headers['Content-Encoding'] + bcolors.RESET
        except:
            return bcolors.FAIL + "hidden"


    def get_date(self):
        """Return current GMT from response header or generate it  manually"""
        try:
            return bcolors.CYAN + self.r.headers['Date'] + bcolors.RESET
        except:
            return bcolors.CYAN + strftime("%a, %d %b %Y %X GMT", gmtime()) + bcolors.RESET


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
        print(bcolors.OKGREEN + "----------------------------Configuration scan-----------------------------")
        print(bcolors.OKGREEN + "---------------------------------------------------------------------------")
        print(bcolors.OKGREEN + f"GET REQUEST with cookie: {self.cookie}")
        print(bcolors.OKGREEN + f"Time of connection: {self.date}")
        print(bcolors.OKGREEN + f"Certificate: {self.certificate}")
        print(bcolors.OKGREEN + f"Server: {self.server}")
        print(bcolors.OKGREEN + f"Operating system: {self.os}")
        print(bcolors.OKGREEN + f"Encoding: {self.encoding}")
        print(bcolors.OKGREEN + f"Programming language: {self.programming_lang}")
        print(bcolors.OKGREEN + f"Compression: {self.compression}")
        print(bcolors.OKGREEN + "--------------------------Search for admin pages---------------------------")
        self.adminpages = search_admin_pages(self.url, progress=0, ext='php' if 'PHP' in self.programming_lang else 'a',
        									 wordlist_file="spider/admin_login.txt")
        print(bcolors.OKGREEN + f"admin/dashboard pages found: {len(self.adminpages)}")
        print(bcolors.OKGREEN + "---------------------------------------------------------------------------")
        print(bcolors.OKGREEN + "-----------------------Search for all website pages------------------------")
        print(bcolors.OKGREEN + "---------------------------------------------------------------------------")
        self.pages = self.get_pages(self.url)
        print(bcolors.OKGREEN + f"Webpages found: {len(self.pages)}")
        print(bcolors.OKGREEN + "---------------------------------------------------------------------------")
        print(bcolors.OKGREEN + "-----------------------Configuration scan completed------------------------")
        print(bcolors.OKGREEN + "---------------------------------------------------------------------------")
        print(bcolors.RESET)


    def get_server(self):
        """Try to get server type from header,
        highlight 'proxy-like' server name with orange
        """
        try:
            return bcolors.CYAN + self.detected['web-servers'] + bcolors.RESET
        except:
            try:
                return bcolors.WARNING + self.r.headers['Server'] + bcolors.RESET
            except:
                return bcolors.FAIL + 'hidden'


    def get_os(self):
        if not self.local:
            try:
                return bcolors.CYAN + self.detected['operating-systems'] + bcolors.RESET
            except:
                return bcolors.FAIL + 'hidden'
        else:
            return bcolors.WANING + platform.platform() + bcolors.RESET + bcolors.HEADER + ' [CURRENT PC]' + bcolors.RESET


    def get_cookie(self):
        try:
            return bcolors.CYAN + self.r.headers['Set-Cookie'] + bcolors.RESET
        except KeyError:
            return bcolors.FAIL + "hidden" + bcolors.RESET


    def get_language(self):
        """Try to get programming language from header"""
        try:
            return bcolors.CYAN + self.detected['programming-languages'] + bcolors.RESET
        except:
            # TODO: https://www.owasp.org/index.php/Testing_for_HTTP_Parameter_pollution_(OTG-INPVAL-004)
            return bcolors.FAIL + 'hidden' + bcolors.RESET


    def get_pages(self, url, no_verbose=False):
        """Return list of all webpages"""
        crawler = Crawler(url, no_verbose)
        return crawler.start()
        