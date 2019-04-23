"""
PHP
Python
C#
Ruby
Java
JavaScript (?)
"""
from safety_db import INSECURE

# https://raw.githubusercontent.com/pyupio/safety-db/master/data/insecure.json
# https://raw.githubusercontent.com/pyupio/safety-db/master/data/insecure_full.json


class CVEchecker:
	"""docstring for CVEchecker"""
	def __init__(self, source):
		self.source = source
		
	def check_github_url(self, string):
		# TODO
		return False

	def detect_language(self, file):
		""""""
			

if __name__ == "__main__":
	print(INSECURE["flask"])