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
		so it's maybe will work faster. Or maybe we will make whole admin page finding here separately
		"""
		self.url = configer.url
		self.adminpages = configer.adminpages
		# TODO

	def start_hack(self):
		print("FAKING THE BLOODY LOGINER")
		print(f"loginer knows admin pages: ")
		for page in self.adminpages:
			print(page)

	def get_raw_html(self, url):
		"""Return HTML page from url"""
		req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
		response = urllib.request.urlopen(req)
		return str(response.read())

	def has_captcha(self, html):
		if 'captcha' in html:
			return True
		else:
			return False

	def has_login_form(self, html):
		"""Return True if html has form with 'login' and 'password' fields"""
		soup = BeautifulSoup(html, 'html.parser')
		form = soup.find("form")
		if form:
			input_fields = form.find_all('input')
			count = 0
			for field in input_fields:
				if field['type'] == 'text':
					# print(field['name'])
					count += 1
				elif field['type'] == 'password':
					# print(field['name'])
					count += 1
			if count == 2:
				# we have both login and password fields
				return True
			else:
				return False
		else:
			return False

if __name__ == "__main__":
	from configer import Configer
	c = Configer('https://inmac.org/login/')
	log = Loginer(c)
	url = input("provide url to check: ")
	html = log.get_raw_html(url)

	print(f"page has CAPTCHA: {log.has_captcha(html)}")
	print(f"page has login form: {log.has_login_form(html)}")
