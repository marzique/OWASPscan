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
from subprocess import check_output
import os
import json
import re
from lxml import etree, objectify
from lxml.etree import XMLSyntaxError
from requests_html import HTMLSession
from packaging import version
import time



########################################################
#########################HELPERS########################
########################################################

def get_list_of_files(dir_name, source_code=True):
    """
    Return list of all files within given directory and subdirectories
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


########################################################
#########################PYTHON#########################
########################################################

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
    """
    Check requirements.txt for vulnurable dependencies,
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

########################################################
###########################PHP##########################
########################################################

def check_php_dependencies(path_to_composer_dot_lock):
    """
    Check composer.lock file for vulnurable dependencies, return list of them. 
    If request limit for API reached - return None.
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

########################################################
#########################C_SHARP########################
########################################################

def xml_validate(some_xml_string, xsd_file):
    """Validate XML file correctness agains schema"""

    try:
        schema = etree.XMLSchema(file=xsd_file)
        parser = objectify.makeparser(schema=schema)
        objectify.fromstring(some_xml_string, parser)
        print(bcolors.OKGREEN + "XML check: OK!")
        return True
    except XMLSyntaxError:
        print(bcolors.OKGREEN + "XML check: OK!")
        return False

def csharp_dependencies_dict(path_to_packages_dot_config):
    """
    Return dict {package: version,} from packages.config file.
    Return None if file is corrupted
    """

    packages_list = {}

    # validate XML 
    with open(path_to_packages_dot_config, "rb") as bytes_for_check:
        if not xml_validate(bytes_for_check.read(), "assets/packages_config.xsd"):
            return None
    
    with open(path_to_packages_dot_config, "r") as fo:
        xml = fo.read()
    
    soup = BeautifulSoup(xml, "xml")
    packages = soup.find_all("package")
    for package in packages:
        packages_list[package["id"]] = package["version"]

    return packages_list


def parse_js_html(url, sleep_time=5):
    """
    Scrape webpage that uses JavaScript to load elements.
    Return HTML.
    """

    session = HTMLSession()
    r = session.get(url)
    r.html.render(sleep=sleep_time)
    return r.html.html


def compare_versions(v1, v2):
    """Return True if v1 > v2, else (<=) - False"""
    return version.parse(v1) > version.parse(v2)

def check_package(package_name, package_version, language):
    """Check vulnurabilities for package:version, return None if not found"""

    url = "https://www.sourceclear.com/vulnerability-database/search#query=" + package_name + "%20language:" + language
    html = parse_js_html(url)
    soup = BeautifulSoup(html, "html.parser")

    # get list of found results
    results = soup.find_all(class_="bo-b--2")
    for result in results:
        found_title = result.a.string
        vulnurabilities_amount = int(result.find(string=re.compile("Number of Vulnerabilities")).parent.findNext(class_='grid__item').string)

        if found_title == package_name:
            if vulnurabilities_amount > 0:
                version_string = result.find(string=re.compile("Latest Version"))
                version = re.findall(r"Latest Version: ([\d.]*\d+)", version_string)[0]
                if not compare_versions(version, package_version):
                    return 0
                    print(bcolors.OKGREEN + f"{package_name} package version {package_version} is safe, no vulnurabilities found.")
                else:
                    print(bcolors.FAIL + f"{package_name} with vulnurable version {package_version} found!" + bcolors.OKGREEN)
                    return vulnurabilities_amount
            else:
                print(bcolors.OKGREEN + f"{package_name} package is safe, no vulnurabilities found.")
                return 0
    # not found any info
    print(bcolors.WARNING + f"No info availible for {package_name}. Skipping..." + bcolors.OKGREEN)
    return None

        
def check_csharp_dependencies(path_to_packages_dot_config):
    """
    Check packages.config file for vulnurable dependencies, return list of them. 
    Using 'https://www.sourceclear.com/vulnerability-database/search#query=' as API
    """
    vulnurable_packages = []

    # get dict of packages
    packages = csharp_dependencies_dict(path_to_packages_dot_config)


    for package in packages:
        vulnurabilities_found = check_package(package, packages[package], "csharp")
        if vulnurabilities_found is not None and vulnurabilities_found >= 1:
            vulnurable_packages.append(package)
    
    return vulnurable_packages


########################################################
###########################RUBY#########################
########################################################

def ruby_gems_load(path_to_gemfile_dot_lock):
    """
    Return gem dict from Gemfile.lock file.
    Return None if file is corrupted.
    """
    gem_dict = {}

    start_record = False
    gems = []

    with open(path_to_gemfile_dot_lock, 'r') as gemfile:
        for line in gemfile:
            # start appending if encounter line with specs:
            if "specs:" in line:
                start_record = True
                continue
            # gems finished
            if "PLATFORMS" in line:
                break
            # add only gem without it's own dependencies
            if start_record:
                if line.startswith("    ") and line[4].isalpha():
                    gems.append(line.strip())
    for gemline in gems:
        gemname, gem_version = gemline[:-1].split(" (")
        gem_dict[gemname] = gem_version
    
    return gem_dict
    

def check_gem_version(gem_name):
    """
    Return gem version from API https://rubygems.org/api/v1/versions/%GEM_NAME%/latest.json, 
    if gem name is wrong (not found) return None
    """

    api_url = "https://rubygems.org/api/v1/versions/" + gem_name + "/latest.json"
    json_response = requests.get(api_url).json()

    # bad gem name
    if json_response["version"] == "unknown":
        return None

    return json_response["version"]


def check_ruby_dependencies(path_to_gemfile_dot_lock):
    """
    Check Gemfile.lock file for vulnurable (read outdated) dependencies, 
    return list of them, if none found return None. 
    """
    vulnurable_gems = []

    gems = ruby_gems_load(path_to_gemfile_dot_lock)

    for gem in gems:
        latest_version = check_gem_version(gem)

        if not latest_version:
            print(bcolors.WARNING + f"{gem} gem not found, skipping" + bcolors.OKGREEN)
            continue

        gem_version = gems[gem]
        if compare_versions(latest_version, gem_version):
            print(bcolors.FAIL + f"{gem} with vulnurable version {gem_version} found!" + bcolors.OKGREEN)
            vulnurable_gems.append(gem)
        else:
            print(bcolors.OKGREEN + f"{gem} gem with version {gem_version} is safe, no vulnurabilities found.")
        
        time.sleep (50.0 / 1000.0) # ~10 requests per second to not reach limit

    return vulnurable_gems
    

########################################################
###########################JAVA#########################
########################################################

def java_dependencies_dict(path_to_pom_dot_xml):
    """
    Return dict {package: version,} from pom.xml file.
    Return None if file is corrupted
    """
    dependencies_list = {}

    with open(path_to_pom_dot_xml, "r") as fo:
        xml = fo.read()
    
    soup = BeautifulSoup(xml, "xml")
    dependencies = soup.find_all("dependency")
    for dependency in dependencies:
        dep_name = dependency.find("artifactId").string
        full_version = dependency.find("version").string

        if not full_version[-1].isdigit():
            # e.g. 3.1.6.asdkjaskd
            dep_version = full_version[:full_version.rindex('.')]
        else:
            # e.g. 1.2.6
            dep_version = full_version

        # check if we explicitly have version which starts from digit
        if dep_version[0].isdigit():
            dependencies_list[dep_name] = dep_version
        else:
            print(bcolors.WARNING + f"{dep_name} dependency version not specified, skipping" + bcolors.OKGREEN)

    return dependencies_list


def check_java_dependencies(path_to_packages_dot_config):
    """
    Check packages.config file for vulnurable dependencies, return list of them. 
    Using 'https://www.sourceclear.com/vulnerability-database/search#query=' as API
    """
    vulnurable_packages = []

    # get dict of packages
    packages = java_dependencies_dict(path_to_packages_dot_config)


    for package in packages:
        vulnurabilities_found = check_package(package, packages[package], "java")
        if vulnurabilities_found is not None and vulnurabilities_found >= 1:
            vulnurable_packages.append(package)
    
    return vulnurable_packages


########################################################
######################MAIN ALGORITHM####################
########################################################



def analyse_folder(path_to_folder):
    language_dep_files = {"python": "requirements.txt",
                          "c#": "packages.config",
                          "php": "composer.lock",
                          "ruby": "Gemfile.lock",
                          "java": "pom.xml"
    }

    vulnurabilities = []

    filenames = get_list_of_files(path_to_folder, False)
    languages = detect_language(filenames)
    main_config = None

    for language in languages:
        dependency_file = language_dep_files[language]
        if dependency_file in filenames:
            print(bcolors.OKGREEN + f"{dependency_file} file found! Starting scan...")
            main_config = language
            break
        elif language != languages[-1]:
            print(bcolors.WARNING + f"{dependency_file} file not found! Checking next language..." + bcolors.OKGREEN)
            continue
    else:
        print(bcolors.FAIL + f"No dependencies file found for any language. Aborting..." + bcolors.OKGREEN)
        return None
    
    if main_config == "python":
        refresh_python_dependencies()
        path = path_to_folder + "/requirements.txt"
        vulnurabilities = check_python_dependencies(path)
    elif main_config == "php":
        path = path_to_folder + "/composer.lock"
        vulnurabilities = check_php_dependencies(path)
    elif main_config == "c#":
        path = path_to_folder + "/packages.config"
        vulnurabilities = check_csharp_dependencies(path)
    elif main_config == "ruby":
        path = path_to_folder + "/Gemfile.lock"
        vulnurabilities = check_ruby_dependencies(path)
    elif main_config == "java":
        path = path_to_folder + "/pom.xml"
        vulnurabilities = check_java_dependencies(path)

    return vulnurabilities


if __name__ == "__main__":

    # DETECT VULNURABILITIES IN requirements.txt                [PYTHON]
    print(check_python_dependencies("tests/vulnurable_reqs.txt"))

    # DETECT VULNURABILITIES IN composer.lock                   [PHP]
    print(check_php_dependencies("tests/composer.lock"))

    # DETECT VULNURABILITIES IN packages.config                 [C#]
    print(check_csharp_dependencies("tests/packages.config"))   

    # DETECT VULNURABILITIES IN Gemfile.lock                    [Ruby]
    print(check_ruby_dependencies("tests/Gemfile.lock"))

    # DETECT VULNURABILITIES IN pom.xml                         [Java]
    print(check_java_dependencies("tests/pom.xml"))  
