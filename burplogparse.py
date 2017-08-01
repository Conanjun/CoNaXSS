#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2017/7/31 17:49
# @Author  : Conan0xff
# @Function: Parse burp log file to objects

import re
import binascii

from lib.core.common import HTTP_HEADER
from lib.core.common import HTTPMETHOD
from lib.core.common import getPublicTypeMembers
from lib.core.common import filterStringValue
from lib.core.common import getUnicode
from lib.core.common import checkFile
from lib.core.common import openFile
from lib.core.settings import BURP_REQUEST_REGEX
from lib.core.settings import BURP_XML_HISTORY_REGEX
from lib.core.settings import CRAWL_EXCLUDE_EXTENSIONS


def _feedTargetsDict(reqFile, targets):
	def _parseBurpLog(content):
		"""
		Parses burp logs
		"""

		if not re.search(BURP_REQUEST_REGEX, content, re.I | re.S):
			if re.search(BURP_XML_HISTORY_REGEX, content, re.I | re.S):
				reqResList = []
				for match in re.finditer(BURP_XML_HISTORY_REGEX, content, re.I | re.S):
					port, request = match.groups()
					try:
						request = request.decode("base64")
					except binascii.Error:
						continue
					_ = re.search(r"%s:.+" % re.escape(HTTP_HEADER.HOST), request)
					if _:
						host = _.group(0).strip()
						if not re.search(r":\d+\Z", host):
							request = request.replace(host, "%s:%d" % (host, int(port)))
					reqResList.append(request)
			else:
				reqResList = [content]
		else:
			reqResList = re.finditer(BURP_REQUEST_REGEX, content, re.I | re.S)

		for match in reqResList:
			request = match if isinstance(match, basestring) else match.group(0)
			request = re.sub(r"\A[^\w]+", "", request)

			schemePort = re.search(r"(http[\w]*)\:\/\/.*?\:([\d]+).+?={10,}", request, re.I | re.S)

			if schemePort:
				scheme = schemePort.group(1)
				port = schemePort.group(2)
				request = re.sub(r"\n=+\Z", "", request.split(schemePort.group(0))[-1].lstrip())
			else:
				scheme, port = None, None

			if not re.search(r"^[\n]*(%s).*?\sHTTP\/" % "|".join(getPublicTypeMembers(HTTPMETHOD, True)), request,
							 re.I | re.M):
				continue

			if re.search(r"^[\n]*%s.*?\.(%s)\sHTTP\/" % (HTTPMETHOD.GET, "|".join(CRAWL_EXCLUDE_EXTENSIONS)), request,
						 re.I | re.M):
				continue

			getPostReq = False
			url = None
			host = None
			method = None
			data = None
			cookie = None
			params = False
			newline = None
			lines = request.split('\n')
			headers = []

			for index in xrange(len(lines)):
				line = lines[index]

				if not line.strip() and index == len(lines) - 1:
					break

				newline = "\r\n" if line.endswith('\r') else '\n'
				line = line.strip('\r')
				match = re.search(r"\A(%s) (.+) HTTP/[\d.]+\Z" % "|".join(getPublicTypeMembers(HTTPMETHOD, True)),
								  line) if not method else None

				if len(line.strip()) == 0 and method and method != HTTPMETHOD.GET and data is None:
					data = ""
					params = True

				elif match:
					method = match.group(1)
					url = match.group(2)
					params = True
					getPostReq = True

				# POST parameters
				elif data is not None and params:
					data += "%s%s" % (line, newline)

				# GET parameters
				elif "?" in line and "=" in line and ": " not in line:
					params = True

				# Headers
				elif re.search(r"\A\S+:", line):
					key, value = line.split(":", 1)
					value = value.strip().replace("\r", "").replace("\n", "")

					# Cookie and Host headers
					if key.upper() == HTTP_HEADER.COOKIE.upper():
						cookie = value
					elif key.upper() == HTTP_HEADER.HOST.upper():
						if '://' in value:
							scheme, value = value.split('://')[:2]
						splitValue = value.split(":")
						host = splitValue[0]

						if len(splitValue) > 1:
							port = filterStringValue(splitValue[1], "[0-9]")

					# Avoid to add a static content length header to
					# headers and consider the following lines as
					# POSTed data
					if key.upper() == HTTP_HEADER.CONTENT_LENGTH.upper():
						params = True

					# Avoid proxy and connection type related headers
					elif key not in (HTTP_HEADER.PROXY_CONNECTION, HTTP_HEADER.CONNECTION):
						headers.append((getUnicode(key), getUnicode(value)))

					# if kb.customInjectionMark in re.sub(PROBLEMATIC_CUSTOM_INJECTION_PATTERNS, "", value or ""):
					#    params = True

			data = data.rstrip("\r\n") if data else data

			if getPostReq and (params or cookie):
				if not port and isinstance(scheme, basestring) and scheme.lower() == "https":
					port = "443"
				elif not scheme and port == "443":
					scheme = "https"

				if not host:
					errMsg = "invalid format of a request file"
					raise Exception, errMsg

				if not url.startswith("http"):
					url = "%s://%s:%s%s" % (scheme or "http", host, port or "80", url)
					scheme = None
					port = None

				# return (url, method, data, cookie, tuple(headers))
				targets.add((url, method, data, cookie, tuple(headers)))

	checkFile(reqFile)
	try:
		with openFile(reqFile, "rb") as f:
			content = f.read()
	except (IOError, OSError, MemoryError), ex:
		errMsg = "something went wrong while trying "
		errMsg += "to read the content of file '%s' ('%s')" % (reqFile, getSafeExString(ex))
		raise Exception(errMsg)

	_parseBurpLog(content)
	if not targets:
		errMsg = "unable to find usable request(s) "
		errMsg += "in provided file ('%s')" % reqFile
		raise Exception(errMsg)

if __name__=='__main__':
	targets=set()
	_feedTargetsDict('temp.log',targets)
	print targets