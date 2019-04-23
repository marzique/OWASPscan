"""PHP, Python, C#, Ruby, Java, JavaScript (?)"""
from safety_db import INSECURE
import requests


class CVEchecker:
	"""docstring for CVEchecker"""
	def __init__(self, source):
		self.source = source
		
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


if __name__ == "__main__":
	print(INSECURE["requests"])