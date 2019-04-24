"""PHP, Python, C#, Ruby, Java, JavaScript (?)
https://github.com/pyupio/safety-db
"""
from safety_db import INSECURE
import requests
from packaging.specifiers import SpecifierSet
from packaging.version import Version
from helpers.colors import bcolors


def check_github_url(self, string):
	# TODO
	return False

def detect_language(self, file):
	""""""
	pass

def refresh_python_dependencies():
	"""Download and refresh insecure.json and insecure_full.json"""
	insecure = requests.get("https://raw.githubusercontent.com/pyupio/safety-db/master/data/insecure.json")
	with open('data/insecure.json','r+') as f:
		#convert to string:
		data = f.read()
		f.seek(0)
		f.write(insecure.text)
		f.truncate()

	insecure_full = requests.get("https://raw.githubusercontent.com/pyupio/safety-db/master/data/insecure_full.json")
	with open('data/insecure_full.json','r+') as f:
		#convert to string:
		data = f.read()
		f.seek(0)
		f.write(insecure.text)
		f.truncate()

def check_python_dependencies(path_to_requirements):
	"""TODO"""

	fo = open(path_to_requirements, "r")
	dependencies = fo.read().splitlines()
	vulnurable = []
	for dependency in dependencies:
		library, version = dependency.split("==")
		try:
			vers = INSECURE[library]
		except KeyError:
			print(bcolors.OKGREEN + f"No vulnurabilites found for {library}")
			continue

		ver = Version(version)
		for specifier in vers:
			if ver in SpecifierSet(specifier):
				print(bcolors.FAIL + f"Vulnurable dependency version for  {dependency}" + bcolors.OKGREEN)
				vulnurable.append(dependency)

	return vulnurable


if __name__ == "__main__":
		
	check_python_dependencies("requirements.1.txt")
