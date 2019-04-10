"""Configurer wrapper"""
import argparse
import sys
from configer import Configer


def start_configer(mode=None, url=None):
    if mode == None or url == None:
        # Parse command-line arguments
        parser = argparse.ArgumentParser()
        parser.add_argument("URL", help="target website")
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("--local", action="store_true", help="localhost server")
        group.add_argument("--enterprise", action="store_true", help="working website")
        args = vars(parser.parse_args())
        if args["local"]:
            local = True
        elif args["enterprise"]:
            local = False
        appdata = Configer(args["URL"], local=local)
        appdata.output_configuration()
    else:
        if mode == 'local':
            local = True
        elif mode == 'enterprise':
            local = False
        appdata = Configer(url, local=mode)
        appdata.output_configuration()


if __name__ == "__main__":
    start_configer()
