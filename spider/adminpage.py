#!/usr/bin/env python
# credit: https://github.com/MonroCoury/admin-panel-finder/blob/master/admin_panel_sniffer.py
from datetime import datetime as dt
import sys, random, optparse
import urllib.request
from urllib.error import  URLError, HTTPError
from tqdm import tqdm
from .soft404 import is_dead


#custom header to avoid being blocked by the website
custom_headers = {'User-Agent': 'Mozilla/5.0'}

def adjusturlName(url):#correct url name for urllib
    if url.startswith("www."):
        url = url[4:]
    if not url.startswith("http"):
        url = "http://" + url
    if url.endswith("/"):
        url = url[:-1]
    return url

def loadWordList(wordlist_file, ext):#load pages to check from dictionary
    try:
        with open(wordlist_file, encoding="utf8") as wlf:
            content = wlf.readlines()
        for i in range(len(content)):
            content[i] = content[i].strip("\n")
        if ext.lower() == "a":
            return content
        else:
            return [element for element in content if element.endswith(ext) or element.endswith("/")]
    except FileNotFoundError:
        sys.exit("Couldn't find wordlist file!")

def search_admin_pages(url, progress=0, ext="a", wordlist_file="admin_login.txt"):
    print("\033[92m")
    resp_codes = {403 : "request forbidden", 401 : "authentication required"}# HTTP response codes
    found = []#list to hold the results we find
    url = adjusturlName(url)#correct url name for urllib
    attempts = loadWordList(wordlist_file, ext)
    
    for link in tqdm(attempts[progress:]): # loop over every page in the wordlist file
        site = url + "/" + link
        try:
            if not is_dead(site):
                found.append(site)
                print(f"\033[1;36m {site} page found! \033[92m")
            progress += 1

        except KeyboardInterrupt: # make sure we don't lose everything should the user get bored
            print()
            break

    if found:
        return found

    else:
        print("\033[93m could not find any panel pages... Make sure you're connected to the internet\n" \
              + "or try a different wordlist. total progress: %s" % progress)
        return []

if __name__ == "__main__":
    search_admin_pages('http://leafus.com.ua', progress=0, ext="php", wordlist_file="admin_login.txt")

    