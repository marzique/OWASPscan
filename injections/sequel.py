"""
source&author https://github.com/tccontre/S3qu3l
edited as embed module by Tarnavskyi Denys
"""
import os
import re
import sys
import argparse
import time 
from helpers.colors import bcolors
from tqdm import tqdm


class Sequel:
    def __init__(self):

        self.pat = pattern
        self.bad_files = {}

    def input_checker(self, target_folder, target_file):
        self.target_file = target_file
        self.target_folder = target_folder
        if self.target_file:
            self.pattern_scan(self.target_file)
        else:
            self.iterate_files()

        return self.bad_files 

    def iterate_files(self):
        # for dirs, subdirs, files in os.walk(self.target_folder):
        
        for dirs, subdirs, files in walklevel(self.target_folder, depth=1):
            for file_ in tqdm(files):
                if file_.endswith(".xml"):
                    print(file_)
                    file_path = os.path.join(dirs, file_)
                    self.pattern_scan(file_path)
                time.sleep (1)

        return

    def scanner(self, list_lines, file_path):

        for key, val in self.pat.items():
            clr = bcolors.WARNING
            if not "reg" in key:
                clr = bcolors.FAIL
            line_num = 1
            # print("Looking for rule: {0}".format(key))
            for line in list_lines:
                pat = self.pat[key]
                m = re.search(pat, line)
                if m:
                    print(bcolors.FAIL + "Found possible injection query!" + bcolors.OKGREEN)
                    print(f" file path     : {file_path}")
                    # print(f" detection     : {key}")
                    print(f" line number   : {line_num}")
                    
                    print(" line of code  :" + clr + line + bcolors.OKGREEN)
                    # print(f" string matched: {m.group()}")
                    # print(f" pattern       : {val}")
                    self.bad_files[file_path] = line

                line_num += 1
        return

    def pattern_scan(self, file_path):
        with open(file_path, 'r') as f:
            list_lines = f.readlines()
        self.scanner(list_lines, file_path)
        return


def walklevel(path, depth = 1):
    """It works just like os.walk, but you can pass it a level parameter
       that indicates how deep the recursion will go.
       If depth is -1 (or less than 0), the full depth is walked.
    """
    # if depth is negative, just walk
    if depth < 0:
        for root, dirs, files in os.walk(path):
            yield root, dirs, files

    # path.count works because is a file has a "/" it will show up in the list
    # as a ":"
    path = path.rstrip(os.path.sep)
    num_sep = path.count(os.path.sep)
    for root, dirs, files in os.walk(path):
        yield root, dirs, files
        num_sep_this = root.count(os.path.sep)
        if num_sep + depth <= num_sep_this:
            del dirs[:]


pattern = \
    {
        "reg01": "[\'|\"][\s|\&|\^|\*][\'|\"]",
        "02": "\'\s(?i)or\s1\=1\slimit\s1\s\-\-\s\-\+",
        "03": "\'\=\"(?i)or\'",
        "04": "\'\s(?i)or\s\'\'[\-|\s|&|\^|\*]\'",
        "reg05": "[\'|\"]\-\|\|0[\'|\"]",
        "reg06": "[\'|\"]\-\|\|0[\'|\"]",
        "reg07": "[\'|\"][\s|\&|\^|\*][\'|\"]",
        "08": "\"\s(?i)or\s\"\"[\-|\s|\&|\^|\*|]\"",
        "09": "\"\s(?i)or\s\"\"[\-|\s|\&|\^|\*|]\"",
        "10": "[\"|\'|\"\)|\'\)]?\s?(?i)or\strue\-\-",
        "11": "[\"|\']\)?\)?\s(?i)or\s\(?\(?[\"|\'][a-zA-Z][\"|\']\)?\)?\=[\"|\']\(?\(?[a-zA-Z]",
        "12": "(?i)or\s2\s(?i)like\s2(?i)or\s1\=1",
        "13": "(?i)or\s1\=1[\-\-|\#|\/\*]",


    }


def main():
    if os.name == "nt":
        os.system('cls')
    else:
        os.system('clear')

    sq = Sequel()
    parser = argparse.ArgumentParser(
        description="possible SQL Injection Finder in HTML, XML and etc...")
    parser.add_argument('-d', '--target_folder',
                        help="the folder files you want to scan", required=True)
    parser.add_argument('-f', '--target_file',
                        help="the file you want to scan", required=False)

    args = vars(parser.parse_args())
    target_file = args['target_file']
    target_folder = args['target_folder']

    sq.input_checker(target_folder, target_file)

    return


if __name__ == "__main__":
    main()
