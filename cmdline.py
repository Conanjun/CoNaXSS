#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2017/7/31 17:49
# @Author  : Conan0xff
# @Function: CmdLines Parser

import sys
import os

from optparse import OptionError
from optparse import OptionGroup
from optparse import OptionParser
from optparse import SUPPRESS_HELP

from lib.core.common import checkSystemEncoding
from lib.core.common import getUnicode
from lib.core.common import dataToStdout
from lib.core.settings import IS_WIN
from lib.core.settings import MAX_HELP_OPTION_LENGTH


def cmdLineParser(argv=None):
	"""
	This function parses the command line parameters and arguments
	"""

	if not argv:
		argv = sys.argv

	checkSystemEncoding()

	# Reference: https://stackoverflow.com/a/4012683 (Note: previously used "...sys.getfilesystemencoding() or UNICODE_ENCODING")
	_ = getUnicode(os.path.basename(argv[0]), encoding=sys.stdin.encoding)

	usage = "%s%s [options]" % ("python " if not IS_WIN else "", \
								"\"%s\"" % _ if " " in _ else _)

	parser = OptionParser(usage=usage)

	# Target options
	target = OptionGroup(parser, "Target", "At least one of these "
										   "options has to be provided to define the target(s)")

	target.add_option("-u", "--url", dest="url", help="Target URL (e.g. \"http://www.site.com/vuln.php?id=1\")")

	target.add_option("-l", dest="logFile", help="Parse target(s) from Burp")
	target.add_option("-r", dest="requestFile", help="Load HTTP request from a file")

	# Request options
	request = OptionGroup(parser, "Request", "These options can be used "
											 "to specify how to connect to the target URL")

	request.add_option("--method", dest="method",
					   help="Force usage of given HTTP method (e.g. PUT)")

	request.add_option("--data", dest="data",
					   help="Data string to be sent through POST")

	request.add_option("--cookie", dest="cookie",
					   help="HTTP Cookie header value")

	# Optimization options
	optimization = OptionGroup(parser, "Optimization", "These options can be used "
											 "to locate a dictionary of payload")

	optimization.add_option("--dict", dest="dict",
					   help="input your dict file path")

	parser.add_option_group(target)
	parser.add_option_group(request)
	parser.add_option_group(optimization)


	# Dirty hack to display longer options without breaking into two lines
	def _(self, *args):
		retVal = parser.formatter._format_option_strings(*args)
		if len(retVal) > MAX_HELP_OPTION_LENGTH:
			retVal = ("%%.%ds.." % (MAX_HELP_OPTION_LENGTH - parser.formatter.indent_increment)) % retVal
		return retVal

	parser.formatter._format_option_strings = parser.formatter.format_option_strings
	parser.formatter.format_option_strings = type(parser.formatter.format_option_strings)(_, parser, type(parser))

	_ = []
	# Reference: https://stackoverflow.com/a/4012683 (Note: previously used "...sys.getfilesystemencoding() or UNICODE_ENCODING")
	for arg in argv:
		_.append(getUnicode(arg, encoding=sys.stdin.encoding))
	argv = _

	try:
		(args, _) = parser.parse_args(argv)
	except UnicodeEncodeError, ex:
		dataToStdout("\n[!] %s\n" % ex.object.encode("unicode-escape"))
		raise SystemExit
	return args
