from jinja2 import Template
import webbrowser
import os
import random


# constants
BAD_PORTS = {21: "ftp", 22: "ssh", 23: "telnet",
             25: "smtp", 53: "dns", 80: "http",
             111: "rpc", 137: "netbios", 443: "https",
             445: "smb"}


def render_report_in_window(c, l):
    """Render new file with results"""

    configuration = configer_report(c)
    login_flaws = loginer_report(l)
    dependencies = None
    injections = None

    with open("report/report_layout.html") as file_:
        template = Template(file_.read())

    lst = [configuration["percentage"], login_flaws["percentage"]]

    percentage = int(sum(lst) / len(lst) )

    with open("report.html", 'w') as filetowrite:
        html = template.render(configuration=configuration, login_flaws=login_flaws, percentage=percentage)
        filetowrite.write(html)

    webbrowser.open('file://' + os.path.realpath("report.html"))


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


def loginer_report(l):
    login_flaws = {}

    if l.bruteforced:
        login_flaws["bruteforce"] = True
        login_flaws["bruteforced"] = l.bruteforced
    else:
        login_flaws["bruteforce"] = False
    login_flaws["captcha"] = l.captcha
    login_flaws["hashing"] = l.hashing
    if l.hashing is not None:
        login_flaws["db_file"] = l.db_file

    max_ = 9
    if login_flaws["bruteforce"]:
        max_ -= 3 - random.random() / 4
        if len(login_flaws["bruteforced"]) > 3:
            max_ -= random.random() / 4
    if not login_flaws["captcha"]:
        max_ -= 2.5 - random.random() / 4
    if not login_flaws["hashing"]:
        max_ -= 3 - random.random() / 4

    login_flaws["percentage"] = int(max_ * 10)

    return login_flaws
