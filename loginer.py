"""TODO"""
# https://medium.com/@ismailakkila/black-hat-python-brute-forcing-html-authentication-forms-455e8f85a70a
# https://stackoverflow.com/questions/11747254/python-brute-force-algorithm
# https://dev.to/presto412/how-i-cracked-the-captcha-on-my-universitys-website-237j

# Good info about password lists:
# http://blog.g0tmi1k.com/2011/06/dictionaries-wordlists/
from helpers.colors import bcolors
from tqdm import tqdm
from bs4 import BeautifulSoup
import urllib.request


class Loginer:
	"""docstring for Loginer"""
	def __init__(self, configer):
		"""TODO: find out if we need to pass whole configer object or just admin pages, 
		so it"s maybe will work faster. Or maybe we will make whole admin page finding here separately
		"""
		self.url = configer.url
		self.adminpages = configer.adminpages 
		self.filtered_pages = []
		# TODO

	def start_hack(self):
		print(bcolors.OKGREEN + "---------------------------------------------------------------------------")
		print(bcolors.OKGREEN + "--------------------------Loginer scan search------------------------------")
		print(bcolors.OKGREEN + "---------------------------------------------------------------------------")
		self.filter_pages(self.adminpages)
		print(bcolors.OKGREEN + "---------------------------Bruteforce check--------------------------------")
		self.bruteforce_attack(self.filtered_pages)
		print(bcolors.OKGREEN + "---------------------------Vocabulary attack-------------------------------")
		self.vocabulary_attack(self.filtered_pages)
		print(bcolors.OKGREEN + "---------------------------------------------------------------------------")
		print(bcolors.OKGREEN + "-------------------------Loginer scan finished-----------------------------")
		print(bcolors.OKGREEN + "---------------------------------------------------------------------------")

	def get_raw_html(self, url):
		"""Return HTML page from url"""
		try:
			req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
			response = urllib.request.urlopen(req)
			return str(response.read())
		except:
			return None

	def has_captcha(self, html):
		if "captcha" in html:
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
						print(bcolors.CYAN + f"{page} has login form!")
				else:
					print(bcolors.WANING + f"{page} has CAPTCHA, ignoring")
			else:
				print(bcolors.FAIL + f"can't parse HTML from: {page}")
		return login_pages

	def bruteforce_attack(self, page_urls):
		pass

	def vocabulary_attack(self, page_urls):
		pass


if __name__ == "__main__":
	from configer import Configer

	settings = {"local": False,
			"page_limit": None,
			}
	c = Configer("https://inmac.org/login/", settings)
	log = Loginer(c)
	
	pages = ["http://leafus.com.ua/", "http://leafus.com.ua/wp-admin", "http://indiana.tours/coming-soon/", 
			 "https://stackoverflow.com/", "https://inmac.org/login/"
			 ]

	log.filter_pages(pages)