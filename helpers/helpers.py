""""""
import re
from urllib.parse import urlparse


def strip_url(url):
    """Return plain domain name
	e.g. https://twitter.com/account/begin_password_reset?lang=fil -> twitter.com
    """
    rec = re.compile(r"https?://(www\.)?")
    # TODO: remove averything after first slash
    stripped = str(rec.sub('', url).strip().strip('/').strip('//'))
    head, _, _ = stripped.partition('/')
    return head

def remove_parameters(url):
    head, _, _ = url.partition('?')
    return head



def get_url_domain(url):
    return urlparse(url).netloc