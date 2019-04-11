#!/usr/bin/python3
# -*- coding: utf-8 -*-
import ssl
import OpenSSL
import socket
import re
from datetime import datetime
from helpers.colors import bcolors
from helpers.helpers import strip_url


def check_site(url):
    """TODO"""
    hostname = strip_url(url)
    port = 443
    try:
        cert = ssl.get_server_certificate((hostname, port))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        date_until = str(datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ'))
        return 'valid until ' + date_until
    except ssl.SSLError as e:
        return bcolors.FAIL + 'certificate not found'
