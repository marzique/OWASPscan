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
from helpers.helpers import strip_url, get_url_domain
from report.reporter import BAD_PORTS
from socket import gethostbyname, socket, AF_INET, SOCK_STREAM
from tqdm import tqdm


class Configer:
    """Get all possible info about app configuration from it's URL"""

    def __init__(self, url, settings):
        self.url = url
        self.settings = settings
        self.local = settings['local']       # check if development mode
        self.r = self.get_headers()          # http request header
        self.detected = getSimple(self.url)  # web-app confifuration
        self.cookie, self.cookie_c = self.get_cookie()
        self.date = self.get_date()
        self.ip, self.ip_c = self.get_ip()
        self.country_code = self.get_country_code(self.ip)
        self.location, self.location_c = self.get_location()
        self.encoding = self.r.encoding
        self.server, self.server_c = self.get_server()
        self.compression, self.compression_c = self.get_compression()
        self.os, self.os_c = self.get_os()
        self.programming_lang, self.programming_lang_c = self.get_language()
        self.certificate, self.certificate_c = self.check_ssl(self.url)
        self.pages = []
        self.adminpages = []
        self.pagelimit = settings["page_limit"]
        self.open_ports = []

        self.elapsed = None

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
            return self.r.headers['Content-Encoding'], bcolors.OKGREEN + self.r.headers['Content-Encoding'] + bcolors.RESET
        except:
            return None, bcolors.CYAN + "hidden" + bcolors.OKGREEN

    def get_date(self):
        """Return current GMT from response header or generate it  manually"""
        try:
            return self.r.headers['Date']
        except:
            return strftime("%a, %d %b %Y %X GMT", gmtime())

    def output_configuration(self):
        """Print human-readable results of analysis"""
        art.spin_dash(2)
        print(bcolors.OKGREEN +
              "###########################################################################")
        print(bcolors.OKGREEN +
              "###########################################################################")
        print()
        art.owasp_scan_header()
        print(bcolors.OKGREEN +
              "###########################################################################")
        print(bcolors.OKGREEN +
              "###########################################################################")
        print()
        print(bcolors.OKGREEN + "Connecting to " +
              bcolors.OKBLUE + self.url + "..." + bcolors.OKGREEN)
        art.update_progress(2)
        print(bcolors.OKGREEN +
              "---------------------------------------------------------------------------")
        print(bcolors.OKGREEN +
              "--------------------------CONFIGER SCAN SEARCH-----------------------------")
        print(bcolors.OKGREEN +
              "---------------------------------------------------------------------------")
        print(bcolors.OKGREEN + f"HTTP cookie: {self.cookie_c}")
        print(bcolors.OKGREEN + f"Server IP address: {self.ip_c}")
        print(bcolors.OKGREEN + f"Server geo location: {self.location_c}, country code: {self.country_code}")
        print(bcolors.OKGREEN + f"Time of connection: {self.date}")
        print(bcolors.OKGREEN + f"Certificate: {self.certificate_c}")
        print(bcolors.OKGREEN + f"Server type: {self.server_c}")
        print(bcolors.OKGREEN + f"Operating system: {self.os_c}")
        print(bcolors.OKGREEN + f"Content encoding: {self.encoding}")
        print(bcolors.OKGREEN +
              f"Programming language: {self.programming_lang_c}")
        print(bcolors.OKGREEN + f"Compression: {self.compression_c}")
        print(bcolors.OKGREEN +
              "-----------------------------Open port scanning-----------------------------")
        self.port_scan()
        print(bcolors.OKGREEN +
              "------------------Search for possible admin/login pages--------------------")
        self.adminpages = search_admin_pages(self.url, progress=0, wordlist_file="spider/admin_login.txt")
        print(bcolors.OKGREEN +
              f"admin/dashboard pages found: {len(self.adminpages)}")
        print(bcolors.OKGREEN +
              "-----------------------Search for all website pages------------------------")
        self.pages = self.get_pages(self.url)
        print(bcolors.OKGREEN + f"Webpages found: {len(self.pages)}")
        print(bcolors.OKGREEN +
              "---------------------------------------------------------------------------")
        print(bcolors.OKGREEN +
              "-----------------------------CONFIGER FINISHED-----------------------------")
        print(bcolors.OKGREEN +
              "---------------------------------------------------------------------------")
        print(bcolors.RESET)

    def get_server(self):
        """Try to get server type from header,
        highlight 'proxy-like' server name with orange
        """
        try:
            return self.detected['web-servers'], bcolors.FAIL + self.detected['web-servers'] + bcolors.RESET
        except:
            try:
                return self.r.headers['Server'], bcolors.WARNING + self.r.headers['Server'] + bcolors.RESET
            except:
                return None, bcolors.CYAN + 'hidden' + bcolors.RESET

    def get_os(self):
        if not self.local:
            try:
                return self.detected['operating-systems'], bcolors.FAIL + self.detected['operating-systems'] + bcolors.RESET
            except:
                return None, bcolors.CYAN + 'hidden' + bcolors.RESET
        else:
            return platform.platform(), bcolors.WARNING + platform.platform() + bcolors.RESET + bcolors.HEADER + ' [CURRENT PC]' + bcolors.RESET

    def get_cookie(self):
        try:
            return self.r.headers['Set-Cookie'], bcolors.OKGREEN + self.r.headers['Set-Cookie'] + bcolors.RESET
        except KeyError:
            return None, bcolors.FAIL + "hidden" + bcolors.OKGREEN

    def get_language(self):
        """Try to get programming language from header"""
        try:
            # 1st try
            return str(self.detected['programming-languages']), bcolors.FAIL + str(self.detected['programming-languages']) + bcolors.RESET
        except KeyError:
            try:
                # 2nd try
                return self.r.headers['X-Powered-By'], bcolors.FAIL + self.r.headers['X-Powered-By'] + bcolors.RESET
            except KeyError:
                # TODO: https://www.owasp.org/index.php/Testing_for_HTTP_Parameter_pollution_(OTG-INPVAL-004)
                return None, bcolors.CYAN + 'hidden' + bcolors.RESET

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
            x509 = OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_PEM, cert)
            date_until = str(datetime.strptime(
                x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ'))
            return True, '\033[1;36mvalid until ' + date_until
        except ssl.SSLError as e:
            print(e)
            return False, bcolors.FAIL + "no OV/DV certificate found"


    def get_ip(self):
        """Return IP address from IP API"""

        api_request = "http://ip-api.com/json/" + get_url_domain(self.url)
        json_response = requests.get(api_request).json()
        
        try:
            ip = bcolors.FAIL
            end = ""
            if "cloudflare" in str(json_response).lower():
                ip = bcolors.WARNING
                end = " [cloudflare]"
            return json_response["query"], ip + json_response["query"] + end + bcolors.OKGREEN
        except KeyError:
            return None, bcolors.CYAN + "hidden" + bcolors.OKGREEN
    

    def get_country_code(self, ip):
        """Return cntr code"""

        api_request = "http://api.ipstack.com/" + ip +"?access_key=36591df2455de4518e2551dafd2acd77"
        json_response = requests.get(api_request).json()
        return json_response["country_code"]


    def get_location(self):
        """Return geo location from IP API"""

        api_request = "http://ip-api.com/json/" + get_url_domain(self.url)
        json_response = requests.get(api_request).json()

        try:
            return json_response["city"] + ", " + json_response["country"], bcolors.WARNING + json_response["city"] + ", " + json_response["country"] + bcolors.OKGREEN

        except KeyError:
            return None, bcolors.CYAN + "hidden" + bcolors.OKGREEN

    def port_scan(self):
        """Return list of active ports"""

        # convert to IPv4
        try:       
            ip = gethostbyname(self.ip.split("::")[0])
            print(f"IPv4: {ip}")
        except:
            print(f"Wrong IP address provided")
            return []

        for port in tqdm(range(20, 446)):
                sckt = socket(AF_INET, SOCK_STREAM)
                response = sckt.connect_ex((ip,  port))
                if (response == 0):
                    clr = bcolors.WARNING
                    if port in BAD_PORTS:
                        clr = bcolors.FAIL
                    print(clr + f"Port {port} is open" + bcolors.OKGREEN)
                    self.open_ports.append(port)
        return self.open_ports


