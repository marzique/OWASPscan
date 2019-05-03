from bs4 import BeautifulSoup
import requests
import requests.exceptions
from urllib.parse import urlsplit
from urllib.parse import urlparse, parse_qs
from collections import deque
import re
from injections.XSS_Test import main as xss_check
from injections.sequel import Sequel as XMLchecker
from helpers.colors import bcolors


class Injector:
    """
    Perform various injection attacks/checks, 
    store info about vulnurabilities found.
    """

    def __init__(self, url, path_to_folder):
        self.url = url
        self.folder = path_to_folder
        self.xss_links = {}  # store url: xss_snippet
        self.injectable_xml_files = {}
        # TODO

    ########################################################
    ########################   XSS   #######################
    ########################################################

    def _check_url_for_xss(self, url_with_get_parameters):
        """Check URL that has parameters for reflected XSS
        POST&GET vector attacks.

        @Return: either successful XSS(JS) snippet or None.
        """
        return xss_check(url_with_get_parameters)
    
    def _get_url_domain(self, url):
        return urlparse(url).netloc

    def _get_all_links_recursive(self, url):
        """Return all internal links from website"""
        
        # get base domain
        domain_main = self._get_url_domain(url)

        # a queue of urls to be crawled
        new_urls = deque([url])

        # a set of urls that we have already been processed
        processed_urls = set()
        # a set of domains inside the target website
        local_urls = set()
        # a set of domains outside the target website
        foreign_urls = set()
        # a set of broken urls
        broken_urls = set()

        # process urls one by one until we exhaust the queue
        while len(new_urls):
            # move next url from the queue to the set of processed urls
            url = new_urls.popleft()

            # ignore links with hash, to prevent infinity loop 
            while "#" in url or domain_main != self._get_url_domain(url):
                if len(new_urls):
                    url = new_urls.popleft()
                else:
                    break
                    
            print(url)
            processed_urls.add(url)
            # get url's content
            # print("Processing %s" % url)
            try:
                response = requests.get(url)
            except (requests.exceptions.MissingSchema, requests.exceptions.ConnectionError, requests.exceptions.InvalidURL, requests.exceptions.InvalidSchema):
                # add broken urls to it's own set, then continue
                broken_urls.add(url)
                continue

            # extract base url to resolve relative links
            parts = urlsplit(url)
            base = "{0.netloc}".format(parts)
            strip_base = base.replace("www.", "")
            base_url = "{0.scheme}://{0.netloc}".format(parts)
            path = url[:url.rfind('/')+1] if '/' in parts.path else url

            # create a beutiful soup for the html document
            soup = BeautifulSoup(response.text, "lxml")

            for link in soup.find_all('a'):
                # extract link url from the anchor
                anchor = link.attrs["href"] if "href" in link.attrs else ''

                if anchor.startswith('/'):
                    local_link = base_url + anchor
                    local_urls.add(local_link)
                elif strip_base in anchor:
                    local_urls.add(anchor)
                elif not anchor.startswith('http'):
                    local_link = path + anchor
                    local_urls.add(local_link)
                else:
                    foreign_urls.add(anchor)

                for i in local_urls:
                    if not i in new_urls and not i in processed_urls:
                        new_urls.append(i)

        return list(processed_urls)

    def _filter_parameter_pages(self, url_list):
        """Return list of url containing at least 1 GET parameter"""

        param_urls = []

        for url in url_list:
            parsed = urlparse(url)
            if parse_qs(parsed.query):
                param_urls.append(url)

        return param_urls

    def xss_attack(self):
        """
        Perform xss attack on website, URL = self.url from object
        return dict containing url: xss_snippet
        """

        print(bcolors.OKGREEN + "Starting XSS attack...")

        all_urls = self._get_all_links_recursive(self.url)
        parameter_urls = self._filter_parameter_pages(all_urls)

        for url in parameter_urls:
            print(bcolors.OKGREEN + f"\nAttacking {url}")
            result = self._check_url_for_xss(url)
            if result:
                self.xss_links[url] = result

        return self.xss_links

    ########################################################
    ########################   SQL   #######################
    ########################################################

    ########################################################
    ########################   XML   #######################
    ########################################################

    def xml_attack(self):
        """Find """
        print(bcolors.OKGREEN + "checking XML files for possible injections...")
        xmler = XMLchecker()
        self.injectable_xml_files = xmler.input_checker(self.folder, None)

        return self.injectable_xml_files

    ########################################################
    ####################   DESERIALIZE   ###################
    ########################################################


    ########################################################
    ##################   MAIN ALGORITHM   ##################
    ########################################################

    def start_injection_attacks(self):
        self.xss_attack()
        self.xml_attack()


if __name__ == "__main__":

    injector = Injector("http://leafus.com.ua", "tests")
    print(injector.xss_attack())
    print(injector.xml_attack())
