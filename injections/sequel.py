"""
source&author https://github.com/tccontre/S3qu3l
edited as embed module by Tarnavskyi Denys
"""
import os
import re
import sys
import argparse
import hashlib


class Sequel:
    def __init__(self):

        self.pat = pattern
        return

    def input_checker(self, target_folder, target_file):
        self.target_file = target_file
        self.target_folder = target_folder
        if self.target_file:
            self.pattern_scan(self.target_file)
        else:
            self.iterate_files()
        return

    def iterate_files(self):
        for dirs, subdirs, files in os.walk(self.target_folder):
            for file in files:
                file_path = os.path.join(dirs, file)
                self.pattern_scan(file_path)
        return

    def scanner(self, list_lines, file_path):

        for key, val in self.pat.items():
            line_num = 1
            print("Looking for rule: {0}".format(key))
            for line in list_lines:
                pat = self.pat[key]
                m = re.search(pat, line)
                if m:
                    print("Found possible SQL command!!")
                    print(" file path     : {0}".format(file_path))
                    print(" detection     : {0}"
                          " line number   : {1}"
                          " line of code  : {2}"
                          " string matched: {3}"
                          " pattern       : {4}".format(key,
                                                        line_num,
                                                        line, m.group(), val))

                line_num += 1
        return

    def pattern_scan(self, file_path):
        with open(file_path, 'r') as f:
            print(" file path: {0}".format(file_path))
            print("-------------------------------------------------------")
            list_lines = f.readlines()
        self.scanner(list_lines, file_path)
        return


pattern = \
    {
        "#01": "[\'|\"][\s|\&|\^|\*][\'|\"]",
        "#02": "\'\s(?i)or\s1\=1\slimit\s1\s\-\-\s\-\+",
        "#03": "\'\=\"(?i)or\'",
        "#04": "\'\s(?i)or\s\'\'[\-|\s|&|\^|\*]\'",
        "#05": "[\'|\"]\-\|\|0[\'|\"]",
        "#06": "[\'|\"]\-\|\|0[\'|\"]",
        "#07": "[\'|\"][\s|\&|\^|\*][\'|\"]",
        "#08": "\"\s(?i)or\s\"\"[\-|\s|\&|\^|\*|]\"",
        "#09": "\"\s(?i)or\s\"\"[\-|\s|\&|\^|\*|]\"",
        "#10": "[\"|\'|\"\)|\'\)]?\s?(?i)or\strue\-\-",
        "#11": "[\"|\']\)?\)?\s(?i)or\s\(?\(?[\"|\'][a-zA-Z][\"|\']\)?\)?\=[\"|\']\(?\(?[a-zA-Z]",
        "#12": "(?i)or\s2\s(?i)like\s2(?i)or\s1\=1",
        "#13": "(?i)or\s1\=1[\-\-|\#|\/\*]",


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
