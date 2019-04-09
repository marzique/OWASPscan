import time
import sys
from colors import bcolors


def spin_dash(seconds):
	"""TODO"""
	animation = "|/-\\"

	for i in range(10 * seconds):
	    time.sleep(0.1)
	    sys.stdout.write("\r" + animation[i % len(animation)])
	    sys.stdout.flush()
	print()

def owasp_scan_header():
	"""TODO"""
	print(" $$$$$$\  $$\      $$\  $$$$$$\   $$$$$$\  $$$$$$$\     ")                                    
	print("$$  __$$\ $$ | $\  $$ |$$  __$$\ $$  __$$\ $$  __$$\      ")                                  
	print("$$ /  $$ |$$ |$$$\ $$ |$$ /  $$ |$$ /  \__|$$ |  $$ | $$$$$$$\  $$$$$$$\ $$$$$$\  $$$$$$$\  ")
	print("$$ |  $$ |$$ $$ $$\$$ |$$$$$$$$ |\$$$$$$\  $$$$$$$  |$$  _____|$$  _____|\____$$\ $$  __$$\ ")
	print("$$ |  $$ |$$$$  _$$$$ |$$  __$$ | \____$$\ $$  ____/ \$$$$$$\  $$ /      $$$$$$$ |$$ |  $$ |")
	print("$$ |  $$ |$$$  / \$$$ |$$ |  $$ |$$\   $$ |$$ |       \____$$\ $$ |     $$  __$$ |$$ |  $$ |")
	print(" $$$$$$  |$$  /   \$$ |$$ |  $$ |\$$$$$$  |$$ |      $$$$$$$  |\$$$$$$$\\ $$$$$$$ |$$ |  $$ |")
	print(" \______/ \__/     \__|\__|  \__| \______/ \__|      \_______/  \_______|\_______|\__|  \__|")
	print()
	print(bcolors.BOLD + "                                 made by Tarnavskyi Denys")
	print()
	