"""TODO"""
import requests
import sys
import platform
from colors import bcolors
from wappalyzer.analyzer import getSimple, getDetail


class Configer:
	"""Get all possible info about app from it's URL"""
	def __init__(self, url, status='enterprise'):
		self.url = url
		self.r = self.get_headers()
		try:
			self.cookie = self.r.headers['Set-Cookie']
		except KeyError:
			self.cookie = bcolors.FAIL + "hidden"

		self.date = self.r.headers['Date']
		self.encoding = self.r.encoding
		self.server = self.r.headers['Server']
		self.compression = self.r.headers['Content-Encoding']
		if status == 'enterprise':
			self.os = bcolors.FAIL + 'TODO'
		else:
			self.os = platform.platform()
		

		print(bcolors.OKGREEN + "###########################################################################")
		print(bcolors.OKGREEN + "###########################################################################")
		print()
		print(bcolors.OKGREEN + "Connecting to " + bcolors.OKBLUE + self.url + bcolors.OKGREEN + "...")
		print(bcolors.OKGREEN + "---------------------------------------------------------------------------")	
		print(bcolors.OKGREEN + f"GET REQUEST with cookie: {self.cookie}")	
		print(bcolors.OKGREEN + f"Time of connection: {self.date}")	
		print(bcolors.OKGREEN + f"Encoding: {self.encoding}")
		print(bcolors.OKGREEN + f"Server: {self.server}")
		print(bcolors.OKGREEN + f"Operating system: {self.os}")
		print(bcolors.OKGREEN + f"Compression: {self.compression}")
		print()
		print(bcolors.OKGREEN + "###########################################################################")
		print(bcolors.OKGREEN + "###########################################################################")


	def get_headers(self):
		"""Get headers from request and handle possible errors"""
		try:
		    r = requests.get(self.url, timeout=3)
		    print(r.headers)
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
		
kek = Configer("https://rex.knu.ua/")

# print(getSimple("https://rex.knu.ua/"))
print(getDetail("https://rex.knu.ua/"))
