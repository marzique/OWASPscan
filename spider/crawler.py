import urllib.request
from urllib.parse import urlsplit, urlunsplit, urljoin, urlparse
from urllib.error import  URLError, HTTPError
import re
import sys
from datetime import datetime
from helpers.helpers import strip_url, remove_parameters

class Crawler:
	"""Crawl website and find all pages from links"""
	def __init__(self, url, exclude=None, domain=None, no_verbose=False, limit=None):
		self.url = self.normalize(url)
		self.host = urlparse(self.url).netloc
		self.domain = domain
		self.exclude = exclude
		self.no_verbose = no_verbose
		self.found_links = []
		self.error_links = []
		self.redirect_links=[]
		self.visited_links = []
		self.limit = limit

	def start(self):
		self.crawl(self.url)
		return self.found_links

	def fix_url(self, url):
		"""TODO"""
		try:
			if url[0] == url[1] == '/':
				return 'http:' + url
			elif url[0] == '/' and url != '/':
				return 'http://' + strip_url(self.url) + url
			else:
				return url
		except:
			return url

	def same_domain(self, link):
		return strip_url(link) == strip_url(self.url)

	def crawl(self, url):
		url = self.fix_url(url)
		if not self.no_verbose:
			print(len(self.found_links) + 1, "Parsing: " + url)
		try:
			# pretend to be mozilla
			req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
			response = urllib.request.urlopen(req)
		except HTTPError as e:
			print('HTTP Error code: ', e.code, ' ', url)
			self.add_url(url, self.error_links, self.exclude)
		except URLError as e:
			print('Error: Failed to reach server. ', e.reason)
		else:
			# Handle redirects
			if url != response.geturl():
				self.add_url(url, self.redirect_links, self.exclude)
				url = response.geturl()
				self.add_url(url, self.visited_links, self.exclude)

			# TODO Handle last modified
			last_modified = response.info()['Last-Modified']
			# Fri, 19 Oct 2018 18:49:51 GMT
			if last_modified:
				dateTimeObject = datetime.strptime(last_modified, '%a, %d %b %Y %H:%M:%S %Z')
#				print ("Last Modified:", dateTimeObject)


			# TODO Handle priority

			self.add_url(url, self.found_links, self.exclude)

			page = str(response.read())
			pattern = '<a [^>]*href=[\'|"](.*?)[\'"].*?>'

			page_links = re.findall(pattern, page)
			links = []

			for link in page_links:
				is_url = self.is_url(link)
				link = self.normalize(link)
				if is_url:
					if self.is_internal(link):
						self.add_url(link, links, self.exclude)
					elif self.is_relative(link):
						link = urljoin( url , link )
						self.add_url(link, links, self.exclude)

			for link in links:
				if self.limit:
					if len(self.visited_links) >= self.limit:
						break

				link = remove_parameters(link)
				if link not in self.visited_links and self.same_domain(link) and len(link) <= 250: # fix this!
					link = self.normalize(link)
					self.visited_links.append(link)
					try:
						self.crawl(link)
					except KeyboardInterrupt:  # make sure we don't lose everything should the user get bored
						print('Stopped by user')
						# return
						break
					except: # bad link?
						continue

	def add_url(self, link, link_list, exclude_pattern=None):
		link = self.normalize(link)
		if link:
			not_in_list = link not in link_list
			excluded = False

			if exclude_pattern:
				excluded = re.search(exclude_pattern, link)

			if not_in_list and not excluded:
				link_list.append(link)


	def normalize(self, url):
		scheme, netloc, path, qs, anchor = urlsplit(url)
		anchor = ''
		return urlunsplit((scheme, netloc, path, qs, anchor))


	def is_internal(self, url):
		host = urlparse(url).netloc
		if self.domain:
		   return self.domain in host
		return host == self.host


	def is_relative(self, url):
		host = urlparse(url).netloc
		return host == ''


	def is_url(self, url):
		scheme, netloc, path, qs, anchor = urlsplit(url)

		if url != '' and scheme in ['http', 'https', '']:
			return True
		else:
			return False
