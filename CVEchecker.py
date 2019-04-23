"""Check given folder/repository for common vulnurabilities using CVE online DB"""
from linguist.libs.file_blob import FileBlob


class CVEchecker:
	"""docstring for CVEchecker"""
	def __init__(self, source):
		self.source = source
		
	def check_github_url(self, string):
		# TODO
		return False

	def detect_language(self, file):
		""""""
		FileBlob(file).language.name
			

if __name__ == "__main__":
	cve = CVEchecker('kek')
	cve.detect_language('loginer.py')