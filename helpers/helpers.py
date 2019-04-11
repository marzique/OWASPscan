""""""
import re


def strip_url(url):
    """Return plain domain name"""
    rec = re.compile(r"https?://(www\.)?")
    return rec.sub('', url).strip().strip('/').strip('//')
