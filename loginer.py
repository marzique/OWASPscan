"""TODO"""

class Loginer:
	"""docstring for Loginer"""
	def __init__(self, configer):
		self.configer = configer
	
	def start_hack(self):
		print("FAKING THE BLOODY LOGINER")
		print(f"loginer knows admin pages: ")
		for page in self.configer.adminpages:
			print(page)