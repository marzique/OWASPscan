from jinja2 import Template
import webbrowser
import os
import random


# constants
BAD_PORTS = {21: "ftp", 22: "ssh", 23: "telnet",
             25: "smtp", 53: "dns", 80: "http",
             111: "rpc", 137: "netbios", 443: "https",
             445: "smb"}


def render_report_in_window(c):
    """Render new file with results"""

    configuration = configer_report(c)
    login = None
    dependencies = None
    injections = None

    with open("report/report_layout.html") as file_:
        template = Template(file_.read())

    with open("report.html", 'w') as filetowrite:
        html = template.render(configuration=configuration)
        filetowrite.write(html)

    webbrowser.open('file://' + os.path.realpath("report.html"))


def parse_security_data(c, l, d, i):
    """Render html page using 4 scan objects"""
    pass


def configer_report(c):
    """
    Return dict of found configuration settings, and security percent
    """

    configuration = {}

    # jumbotron info
    configuration["url"] = c.url
    configuration["cookie"] = c.cookie
    configuration["compression"] = c.compression
    configuration["encoding"] = c.encoding
    configuration["start_time"] = c.date.split()[4]
    configuration["elapsed"] = c.elapsed
    configuration["ip"] = c.ip
    configuration["location"] = c.location
    configuration["country_code"] = c.country_code.lower()

    # detected info
    configuration["server"] = c.server
    if c.server:
        configuration["server"] = c.server.split("/")[0]

    configuration["os"] = c.os
    configuration["language"] = c.programming_lang
    configuration["https"] = c.certificate
    configuration["pages"] = c.pages
    configuration["admin_pages"] = c.adminpages
    configuration["ports"] = {}
    for port in c.open_ports:
        if port in BAD_PORTS:
            configuration["ports"][port] = False
        else:
            s
            configuration["ports"][port] = True

    max_ = 10
    if configuration["os"]:
        max_ -= 2 - random.random() / 4
    if configuration["language"]:
        max_ -= 2 - random.random() / 4
    if not configuration["https"]:
        max_ -= 2 - random.random() / 4
    if len(configuration["admin_pages"]) >= 3:
        max_ -= 2 - random.random() / 4
    if not all(configuration["ports"]):
        max_ -= 2 - random.random() / 4

    configuration["percentage"] = int(max_ * 10)

    return configuration
