"""PHP, Python, C#, Ruby, Java, JavaScript (?)
https://github.com/pyupio/safety-db
"""
from safety_db import INSECURE
import requests
from packaging.specifiers import SpecifierSet
from packaging.version import Version


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

def check_python_dependencies(dependencies):
	"""TODO"""
	vulnurable = []
	for dependency in dependencies:
		library, version = dependency.split("==")
		try:
			vers = INSECURE[library]
			# print(f"{library} has vulnurable versions: {vers}")
			# TODO
		except KeyError:
			print(f"No vulnurabilites found in database for {library}")
			continue

		ver = Version(version)
		for specifier in vers:
			if ver in SpecifierSet(specifier):
				print(f"we have bad dependency {dependency}")
				vulnurable.append(dependency)
	print("bad dependencies:")
	print(vulnurable)






if __name__ == "__main__":
	fo = open("requirements.1.txt", "r")
	check_python_dependencies(fo.read().splitlines())
	# check_python_dependencies(["bs4", "flask", "tqdm"])
