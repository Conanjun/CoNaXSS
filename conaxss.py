#!/usr/bin/env python
# !CoNaXSS
# !Cross-Site Scripting Bruteforcer
# !Author: Conan0xff

from string import whitespace
import httplib
import urllib2
import urllib
import socket
import urlparse
import os
import sys
import time
from colorama import init, Style, Back, Fore
import mechanize
import httplib

from lib.core.data import cmdLineOptions
from cmdline import cmdLineParser
from burplogparse import _feedTargetsDict

init(autoreset=True)


class ConaXSS(object):
	def __init__(self, options):
		self.options = options
		self.options['dict'] = options['dict'] if options['dict'] is not None else 'wordlist.txt'

		self.targets = set()
		self.payloadlist = []

	def _wordlistimport(self):
		try:
			with open(self.options['dict'], 'r') as f:  # Importing Payloads from specified wordlist.
				print(Style.DIM + Fore.WHITE + "[+] Loading Payloads from specified wordlist..." + Style.RESET_ALL)
				for line in f:
					final = str(line.replace("\n", ""))
					self.payloadlist.append(final)
		except IOError:
			print(Style.BRIGHT + Fore.RED + "[!] Wordlist not found!" + Style.RESET_ALL)
			exit()

	def exploit(self):
		if self.options['logFile'] is not None:  # set attr from logFile
			_feedTargetsDict(self.options['logFile'], self.targets)
			for target in self.targets:
				print 'testing target: ', target[0]
				self._single_target_exploit(target)
		elif self.options['requestFile'] is not None:
			_feedTargetsDict(self.options['requestFile'],self.targets)
			for target in self.targets:
				print 'testing target:', target[0]
				self._single_target_exploit(target)
		else:
			target = (self.options['url'], self.options['method'], self.options['data'], self.options['cookie'],
					  None)
			self._single_target_exploit(target)

	# (url,method,data,cookie,turple(headers))
	def _single_target_exploit(self, target):
		url, method, data, cookie, headers = target
		if method == 'GET':
			try:
				grey = Style.DIM + Fore.WHITE
				site = url
				if 'https://' in url:
					pass
				elif 'http://' in url:
					pass
				else:
					site = "http://" + url

				if headers is None:
					headers = {
						'User-agent': 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1',
						'Referer': site,
						'Accept-Encoding': 'gzip,deflate',
						'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
					}
				else:
					temp_headers = {}
					for i in headers:
						temp_headers[i[0]] = i[1]
					headers = temp_headers

				if cookie is not None:
					headers['Cookie'] = cookie

				if len(self.payloadlist) == 0:
					self._wordlistimport()

				para_name_and_value = []
				o = urlparse.urlparse(site)
				parameters = urlparse.parse_qs(o.query, keep_blank_values=True)
				path = urlparse.urlparse(site).scheme + "://" + urlparse.urlparse(site).netloc + urlparse.urlparse(
					site).path
				for para in parameters:  # Arranging parameters and values.
					for i in parameters[para]:
						para_name_and_value.append((para, i))

				total = 0
				vul_url_and_payload = []
				for pn, pv in para_name_and_value:  # Scanning the parameter.
					print(grey + "[+] Testing '" + pn + "' parameter..." + Style.RESET_ALL)
					for x in self.payloadlist:  #
						validate = x.translate(None, whitespace)
						if validate == "":
							pass
						else:
							enc = urllib.quote_plus(x)
							data = path + "?" + pn + "=" + pv + enc
							tmp_req = urllib2.Request(data, headers=headers)
							page = urllib2.urlopen(tmp_req)
							sourcecode = page.read()
							if x in sourcecode:
								print(Style.BRIGHT + Fore.RED + "\n[!]" + " XSS Vulnerability Found! \n" + Fore.RED + Style.BRIGHT + "[!]" + " Parameter:\t%s\n" + Fore.RED + Style.BRIGHT + "[!]" + " Payload:\t%s\n" + Style.RESET_ALL) % (
										 pn, x)
								total = total + 1
								vul_url_and_payload.append((pn, x))
								break
							else:
								pass
					if total == 0:
						print(
								 Style.BRIGHT + Fore.GREEN + "\n[+]" + Style.RESET_ALL + Style.DIM + Fore.WHITE + " '%s' parameter not vulnerable." + Style.RESET_ALL) % pn
				return vul_url_and_payload
			except(KeyboardInterrupt) as Exit:
				print("\nExit...")

		elif method == 'POST':
			try:
				try:
					try:
						br = mechanize.Browser()
						if headers is None:
							br.addheaders = [('User-agent', 'Mozilla/5.0 (Windows; U; Windows NT 5.1; it; rv:1.8.1.11)Gecko/20071127 Firefox/2.0.0.11')]
						else:
							br.addheaders = list(headers)
						br.set_handle_robots(False)
						br.set_handle_refresh(False)

						site = url
						if 'https://' in site:
							pass
						elif 'http://' in site:
							pass
						else:
							site = "http://" + site
						path = urlparse.urlparse(site).scheme + "://" + urlparse.urlparse(
							site).netloc + urlparse.urlparse(site).path

						param = data

						if cookie is not None:
							br.addheaders.append(('Cookie', cookie))

						if len(self.payloadlist) ==0:
							self._wordlistimport()

						grey = Style.DIM + Fore.WHITE
						params = "http://www.site.com/?" + param
						o = urlparse.urlparse(params)
						parameters = urlparse.parse_qs(o.query, keep_blank_values=True)
						paraname = []
						paravalue = []
						for para in parameters:  # Arranging parameters and values.
							for i in parameters[para]:
								paraname.append(para)
								paravalue.append(i)
						total = 0
						pname1 = []  # parameter name
						payload1 = []
						for pn, pv in zip(paraname, paravalue):  # Scanning the parameter.
							print(grey + "[+] Testing '" + pn + "' parameter..." + Style.RESET_ALL)
							for i in self.payloadlist:
								validate = i.translate(None, whitespace)
								if validate == "":
									pass
								else:
									pname1.append(pn)
									payload1.append(str(i))
									d4rk = 0
									for m in range(len(paraname)):
										d = paraname[d4rk]
										d1 = paravalue[d4rk]
										if pn in d:
											d4rk = d4rk + 1
										else:
											d4rk = d4rk + 1
											pname1.append(str(d))
											payload1.append(str(d1))
									data = urllib.urlencode(dict(zip(pname1, payload1)))
									r = br.open(path, data)
									sourcecode = r.read()
									pname1 = []
									payload1 = []
									if i in sourcecode:
										print(
												 Style.BRIGHT + Fore.RED + "\n[!]" + " XSS Vulnerability Found! \n" + Fore.RED + Style.BRIGHT + "[!]" + " Parameter:\t%s\n" + Fore.RED + Style.BRIGHT + "[!]" + " Payload:\t%s\n" + Style.RESET_ALL) % (
												 pn, i)
										total = total + 1
										break
							if total == 0:
								print(
										 Style.BRIGHT + Fore.GREEN + "\n[+]" + Style.RESET_ALL + Style.DIM + Fore.WHITE + " '%s' parameter not vulnerable." + Style.RESET_ALL) % pn
					except(httplib.HTTPResponse, socket.error) as Exit:
						print(Style.BRIGHT + Fore.RED + "[!] Site " + " is offline!" + Style.RESET_ALL)
				except(KeyboardInterrupt) as Exit:
					print("\nExit...")
			except (mechanize.HTTPError, mechanize.URLError) as e:
				print(Style.BRIGHT + Fore.RED + "\n[!] HTTP ERROR! %s %s" + Style.RESET_ALL) % (e.code, e.reason)
			pass
		else:
			msg = 'wrong method'
			raise Exception(msg)


banner = """                                                                                       
	 #####          #     #
	#     #   ####  ##    #    ##    #    #   ####    ####
	#        #    # # #   #   #  #    #  #   #       #
	#        #    # #  #  #  #    #    ##     ####    ####
	#        #    # #   # #  ######    ##         #       #
	#     #  #    # #    ##  #    #   #  #   #    #  #    #
	 #####    ####  #     #  #    #  #    #   ####    ####


	CoNaXSS - Cross-Site Scripting Inject Tool
 
 	Author: Conan0xff
  
"""

if __name__ == '__main__':
	print Style.BRIGHT + Fore.GREEN + banner
	cmdLineOptions.update(cmdLineParser().__dict__)
	cxss = ConaXSS(cmdLineOptions)
	cxss._wordlistimport()
	cxss.exploit()

'''
'''
