from jinja2 import Template
import webbrowser
import os
import random
from datetime import datetime


# constants
BAD_PORTS = {21: "ftp", 22: "ssh", 23: "telnet",
             25: "smtp", 53: "dns", 80: "http",
             111: "rpc", 137: "netbios", 443: "https",
             445: "smb"}


def render_report_in_window(c, l, d):
    """Render new file with results"""

    configuration = configer_report(c)
    login_flaws = loginer_report(l)
    dependencies = dependencies_report(d)
    injections = None

    with open("report/report_layout.html") as file_:
        template = Template(file_.read())

    lst = [configuration["percentage"], login_flaws["percentage"], dependencies["percentage"]]

    percentage = int(sum(lst) / len(lst) )

    with open("report.html", 'w') as filetowrite:
        html = template.render(configuration=configuration, login_flaws=login_flaws, dependencies=dependencies, percentage=percentage)
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
    if configuration["cookie"]:
        configuration["cookie_age"] = None
        cookie_expires = [expires.split("=")[1] for expires in configuration["cookie"].split("; ") if expires.startswith("expires")]
        if cookie_expires:
            try:
                timestart = datetime.strptime(c.date, '%a, %d %b %Y %X GMT')
            except:
                timestart = datetime.strptime(c.date, '%a, %d %b %y %X GMT')
            for expire in cookie_expires:
                try:
                    timefinish = datetime.strptime(c.date, '%a, %d %b %Y %X GMT')
                except:
                    timefinish = datetime.strptime(c.date, '%a, %d %b %y %X GMT')
                maxage = (timefinish - timestart)
                hours = maxage.total_seconds() / 3600
                if configuration["cookie_age"] is None:
                    configuration["cookie_age"] = hours
                elif configuration["cookie_age"] > hours:
                    configuration["cookie_age"] = hours


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
        configuration["ports"][port] = BAD_PORTS[port]


    max_ = 0
    if configuration["cookie"] and configuration["cookie_age"]:
        if configuration["cookie_age"] < 24:
            max_ += 1 + (random.random() / 10)
        elif configuration["cookie_age"] > 24 and configuration["cookie_age"] < 720:
            max_ += 0.6 + (random.random() / 10)
    else:
        max_ += 1
    if configuration["os"]:
        max_ += 1 + (random.random() / 10)
    if configuration["server"] and "cloudflare" not in configuration["server"]:
        max_ += 1 + (random.random() / 10)
    if configuration["language"]:
        max_ += 1 + (random.random() / 10)
    if not configuration["https"]:
        max_ += 1 + (random.random() / 10)
    if len(configuration["admin_pages"]) >= 3:
        max_ += 1 + (random.random() / 10)
    if not all(configuration["ports"]):
        max_ += 1 + (random.random() / 10)

    configuration["percentage"] = int(100 - percentage(max_, 7))

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

    max_ = 0
    if login_flaws["bruteforce"]:
        max_ += 1 + (random.random() / 10)
        if len(login_flaws["bruteforced"]) > 3:
            max_ += 0.5 + (random.random() / 100)
    if not login_flaws["captcha"]:
        max_ += 1 + (random.random() / 10)
    if not login_flaws["hashing"]:
        max_ -= 1 + (random.random() / 10)

    login_flaws["percentage"] = int(100 - percentage(max_, 4))

    return login_flaws

def dependencies_report(d):
    dependencies = {}
    if d.vulnurabilities:
        dependencies["dependency_file"] = d.dependency_file
        dependencies["vulnurabilities"] = d.vulnurabilities
        dependencies["language"] = d.main_language
        dependencies["percentage"] = int(random.random() * 10)
    else:
        dependencies["vulnurabilities"] = None
        dependencies["percentage"] = 50
        
    return dependencies

def percentage(value, total, multiply=True):
	"""
	Accepts two integers, a value and a total. 
	
	The value is divided into the total and then multiplied by 100, 
	returning its percentage as a float.
	
	If you don't want the number multiplied by 100, set the 'multiply'
	kwarg to False.
	
	If one of the numbers is zero, a null value is returned.
	
	h3. Example usage
	
		>> import calculate
		>> calculate.percentage(2, 10)
		20.0
		
	h3. Documentation
	
		* "percentage":http://en.wikipedia.org/wiki/Percentage
	
	"""
	if not isinstance(value, (int, float)):
		return ValueError(f"Input values should be a number, your first input is a {type(value)}")
	if not isinstance(total, (int, float)):
		return ValueError(f"Input values should be a number, your second input is a {type(total)}")
	try:
		percent = (value / float(total))
		if multiply:
			percent = percent * 100
		return percent
	except ZeroDivisionError:
		return None
