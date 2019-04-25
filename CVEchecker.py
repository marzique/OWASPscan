"""PHP, Python, C#, Ruby, Java, JavaScript (?)
https://github.com/pyupio/safety-db
"""
from safety_db import INSECURE
import requests
from packaging.specifiers import SpecifierSet
from packaging.version import Version
from helpers.colors import bcolors
import os
import glob

def get_list_of_files(dir_name, extensions=None):
    """Return list of all source code files within given directory and subdirectories"""

    # create a list of file and sub directories
    # names in the given directory
    list_of_files = os.listdir(dir_name)
    if not extensions:
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
    # leave only source code files
    source_code_filenames = [source for source in filenames_only if source.endswith(extensions)]

    return source_code_filenames


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
        f.write(insecure.text)
        f.truncate()

def check_python_dependencies(path_to_requirements):
    """Check requirements.txt for vulnurable dependencies,
    return them"""

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


if __name__ == "__main__":
    path = os.getcwd()
    print(detect_language(get_list_of_files(path)))

    # check_python_dependencies("vulnurable_reqs.txt")
