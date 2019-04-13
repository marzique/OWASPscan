"""Module's wrapper"""
import argparse
import sys
from configer import Configer
from loginer import Loginer


def start_configer(mode=None, url=None):
    if not mode or not url:
        print('url or mode not privided')
        sys.exit(1)
    if mode == 'local':
        local = True
    elif mode == 'enterprise':
        local = False
    c = Configer(url, local=local)
    c.output_configuration()
    return c

def start_loginer(c):
    l = Loginer(c)
    l.start_hack()


if __name__ == "__main__":
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
    c = Configer(args["URL"], local=local)
    c.output_configuration()
    l = Loginer()
    l.start_hack()
