"""Module's wrapper"""
import argparse
import sys
from configer import Configer
from loginer import Loginer
from dependencer import Dependencer
from injector import Injector


def start_configer(settings, url=None):
    # do we need this double check? TODO
    if not settings or not url:
        print('url or settings not privided')
        sys.exit(1)
    c = Configer(url, settings)
    c.output_configuration()
    return c

def start_loginer(c):
    l = Loginer(c)
    l.start_hack()
    return l

def start_dependencer(folder):
    d = Dependencer(folder)
    d.analyse_folder()
    return d


def start_injector(url, folder, pagelimit):
    i = Injector(url, folder, pagelimit)
    i.start_injection_attacks()
    return i
    
