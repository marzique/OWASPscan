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
		self.bruteforcable = None
		self.captcha = None
		# TODO

	def start_hack(self):
		print("FAKING THE BLOODY LOGINER")
		print(f"loginer knows admin pages: ")
		for page in self.adminpages:
			print(page)

	def get_pages_with_forms(self, page_list):
		for page in page_list:
			pass

	def get_raw_html(self, url):
		"""TODO"""
		req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
		response = urllib.request.urlopen(req)
		html = response.read()

		return str(html)

	def has_captcha(self, html):
		if 'captcha' in html:
			return True
		else:
			return False

if __name__ == "__main__":
	log = Loginer('kek')
	html = log.get_raw_html('https://rex.knu.ua/wp/wp-login.php')

	print(log.has_captcha(html))
