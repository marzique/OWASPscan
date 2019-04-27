"""~PHP~, ~Python~, C#, Ruby, Java, JavaScript (?)
https://github.com/pyupio/safety-db
"""
from safety_db import INSECURE
import requests
from packaging.specifiers import SpecifierSet
from packaging.version import Version
from helpers.colors import bcolors
from tqdm import tqdm
from bs4 import BeautifulSoup
from itertools import cycle
from subprocess import check_output
import numpy as np
import traceback
import os
import glob
import requests
import json



def get_list_of_files(dir_name, source_code=True):
    """Return list of all files within given directory and subdirectories
    source_code parameter used to return only source code files
    """

    # create a list of file and sub directories
    # names in the given directory
    list_of_files = os.listdir(dir_name)
    
    extensions = (".py", ".cs", ".jar", "java", ".php", ".rb")
    all_files = list()
    # Iterate over all the entries
    for entry in list_of_files:
        # Create full path
        full_path = os.path.join(dir_name, entry)
        # If entry is a directory then get the list of files in this directory
        if os.path.isdir(full_path):
            all_files = all_files + get_list_of_files(full_path)
        else:
            all_files.append(full_path)

    # remove paths
    filenames_only = [path_name.rsplit('/', 1)[-1] for path_name in all_files]
    if source_code:
        # leave only source code files
        filenames_only = [source for source in filenames_only if source.endswith(extensions)]

    return filenames_only


def check_github_url(self, string):
    # TODO
    return False

def detect_language(list_of_files):
    """Return list of programming languages used from input list of files"""

    programming_languages = []
    for f in list_of_files:
        if f.endswith(".py"):
            programming_languages.append("python")
        elif f.endswith(".cs"):
            programming_languages.append("c#")
        elif f.endswith(".php"):
            programming_languages.append("php")
        elif f.endswith(".rb"):
            programming_languages.append("ruby")
        elif f.endswith((".jar", ".java")):
            programming_languages.append("java")
    return list(set(programming_languages))


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
        f.write(insecure_full.text)
        f.truncate()

def check_python_dependencies(path_to_requirements):
    """Check requirements.txt for vulnurable dependencies,
    return them
    """

    vulnurable = []
    fo = open(path_to_requirements, "r")
    dependencies = fo.read().splitlines()
    for dependency in dependencies:
        library, version = dependency.split("==")
        # try to get vulnurable versions of library
        try:
            vers = INSECURE[library.lower()]
        except KeyError:
            print(bcolors.OKGREEN + f"No vulnurabilites found for {library}")
            #
            continue

        ver = Version(version)
        for specifier in vers:
            if ver in SpecifierSet(specifier):
                print(bcolors.FAIL + f"Vulnurable dependency version for  {dependency}" + bcolors.OKGREEN)
                vulnurable.append(dependency)
            else:
                print(bcolors.OKGREEN + f"Dependency version is not vulnurable for  {dependency, specifier}" + bcolors.OKGREEN)
    return vulnurable


def check_php_dependencies(path_to_composer_dot_lock):
    """Check composer.lock file for vulnurable dependencies,
    return them
    """
    # https://github.com/FriendsOfPHP/security-advisories - THANKS FOR API (fuck you for requests limit)!
    #  curl -H "Accept: application/json" https://security.symfony.com/check_lock -F lock=@/path/to/composer.lock

    vulnurable = []

    # request to API stuff
    headers = {'Accept': 'application/json',}
    files = {'lock': (path_to_composer_dot_lock, open(path_to_composer_dot_lock, 'rb')),}

    try:
        print(bcolors.OKGREEN + f"Parsing results via requests...")
        json_response = requests.post('https://security.symfony.com/check_lock',
                                        headers=headers,
                                        files=files,
                                        ).json()
        if "error" in json_response:
            print(bcolors.WARNING + f"Request limit for API exceeded!" + bcolors.OKGREEN)
            raise Exception

    except:
        # try to get results via cURL once (after 1st requests attempt)
        print(bcolors.OKGREEN + f"Can't parse via requests, trying cURL call to API" + bcolors.OKGREEN)
        try:
            cmd = ["curl", "-H", "Accept: application/json", "https://security.symfony.com/check_lock", "-F", "lock=@tests/composer.lock"]
            json_response = check_output(cmd)
            if "error" in json_response:
                print(bcolors.WARNING + f"Request limit for API exceeded!" + bcolors.OKGREEN)
                raise Exception
        except:
            print(bcolors.OKGREEN + f"cURL request to API failed" + bcolors.OKGREEN)
            return None

    if json_response:
        for k in json_response:
            ver = json_response[k]["version"]
            print(bcolors.FAIL + f"Vulnurable dependency version found  {k}=={ver}" + bcolors.OKGREEN)
            vulnurable.append(f"{k}=={ver}")
    else:
        print(bcolors.OKGREEN + f"No vulnurabilites found")

    return vulnurable


def check_csharp_dependencies():
    pass

def check_ruby_dependencies():
    pass

def check_java_dependencies():
    pass

if __name__ == "__main__":
    # get all files and PL
    # path = os.getcwd()
    # print(get_list_of_files(path, False))
    # print(detect_language(get_list_of_files(path)))

    # DETECT VULNURABILITIES IN REQ.TXT [PYTHON]
    # pyvul = check_python_dependencies("tests/vulnurable_reqs.txt")
    # print(pyvul)


    print(check_php_dependencies(os.getcwd() + "/tests/composer.lock"))

