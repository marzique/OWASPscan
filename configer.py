"""TODO"""
import requests
import sys
import platform
from time import gmtime, strftime
from helpers.colors import bcolors
from wappalyzer.analyzer import getSimple, getDetail
import helpers.ascii_art as art
from checkssl import check_site
from helpers.helpers import strip_url
from bs4 import BeautifulSoup
import requests
from tqdm import tqdm


class Configer:
    """Get all possible info about app configuration from it's URL"""
    def __init__(self, url, local=False):
        self.url = url
        self.local = local                   # check if development mode
        self.r = self.get_headers()          # http request header
        self.detected = getSimple(self.url)  # web-app confifuration
        self.cookie = self.get_cookie()
        self.date = self.get_date()
        self.encoding = self.r.encoding
        self.server = self.get_server()
        self.compression = self.get_compression()
        self.os = self.get_os()
        self.programming_lang = self.get_language()
        self.certificate = check_site(self.url)
        self.pages = []

    def fix_url(self, url):
        """TODO"""
        try:
            if url[0] == url[1] == '/':
                return 'http:' + url
            elif url[0] == '/' and url != '/':
                return 'http://' + strip_url(self.url) + url
            else:
                return url
        except:
            return url


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
        """TODO"""
        try:
            return self.r.headers['Content-Encoding']
        except:
            return bcolors.FAIL + "hidden"

    def get_date(self):
        """Return current GMT time from response header or manually"""
        try:
            return self.r.headers['Date']
        except:
            return strftime("%a, %d %b %Y %X GMT", gmtime())

    def output_configuration(self):
        """Print human-readable results of analysis"""
        # art.spin_dash(2)
        art.spin_dash(2)
        print(bcolors.OKGREEN + "###########################################################################")
        print(bcolors.OKGREEN + "###########################################################################")
        print()
        art.owasp_scan_header()
        print(bcolors.OKGREEN + "###########################################################################")
        print(bcolors.OKGREEN + "###########################################################################")
        print()
        print(bcolors.OKGREEN + "Connecting to " + bcolors.OKBLUE + self.url + bcolors.OKGREEN + "...")
        # ascii_art.spin_dash(4)
        art.update_progress(2)
        print(bcolors.OKGREEN + "---------------------------------------------------------------------------")
        print(bcolors.OKGREEN + "----------------------------Configuration scan-----------------------------")
        print(bcolors.OKGREEN + "---------------------------------------------------------------------------")
        print(bcolors.OKGREEN + f"GET REQUEST with cookie: {self.cookie}")
        print(bcolors.OKGREEN + f"Time of connection: {self.date}")
        print(f"Certificate: {self.certificate}")
        print(bcolors.OKGREEN + f"Server: {self.server}")
        print(bcolors.OKGREEN + f"Operating system: {self.os}")
        print(bcolors.OKGREEN + f"Encoding: {self.encoding}")
        print(bcolors.OKGREEN + f"Programming language: {self.programming_lang}")
        print(bcolors.OKGREEN + f"Compression: {self.compression}")
        print(bcolors.OKGREEN + "---------------------------------------------------------------------------")
        print(bcolors.OKGREEN + "--------------------------Page spider crawl...-----------------------------")
        print(bcolors.OKGREEN + "---------------------------------------------------------------------------")
        self.pages = self.get_pages(self.url)
        if len(self.pages) > 99:
            print(bcolors.WARNING, end='')
        print(bcolors.OKGREEN + f"Number of pages: {len(self.pages)}")
        print(self.pages)
        print()
        print(bcolors.RESET)

    def get_server(self):
        """TODO"""
        try:
            return self.detected['web-servers']
        except:
            try:
                return bcolors.WARNING + self.r.headers['Server']
            except:
                return bcolors.FAIL + 'hidden'

    def get_os(self):
        """TODO"""
        if not self.local:
            try:
                return self.detected['operating-systems']
            except:
                return bcolors.FAIL + 'hidden'
        else:
            return platform.platform() + bcolors.HEADER + ' [CURRENT PC]'

    def get_cookie(self):
        """TODO"""
        try:
            return self.r.headers['Set-Cookie']
        except KeyError:
            return bcolors.FAIL + "hidden"

    def get_language(self):
        """TODO"""
        try:
            return self.detected['programming-languages']
        except:
            # TODO: https://www.owasp.org/index.php/Testing_for_HTTP_Parameter_pollution_(OTG-INPVAL-004)
            return bcolors.FAIL + 'hidden'

    def get_links_on_page(self, url):
        """return list of all unique links on current page"""
        links = []
        # Getting the webpage, creating a Response object.
        response = requests.get(self.fix_url(url))
        # Extracting the source code of the page.
        data = response.text
        # Passing the source code to BeautifulSoup to create a BeautifulSoup object for it.
        soup = BeautifulSoup(data, 'lxml')
        # Extracting all the <a> tags into a list.
        tags = soup.find_all('a')
        # Extracting URLs from the attribute href in the <a> tags.
        for tag in tags:
            if tag.get('href') and (strip_url(self.url) in tag.get('href') or tag.get('href')[0] == '/'):
                links.append(tag.get('href'))
        return list(set(links))

    def get_pages(self, url):
        """Visit all pages possible and return them, stop count on 100"""
        links = self.get_links_on_page(self.url)
        visited = [self.url]
        for page in tqdm(links, desc='links', unit_scale=1):
            if page not in visited:
                links.extend(self.get_links_on_page(page))
                visited.append(page)
        return visited

