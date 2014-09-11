#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

from __future__ import division, absolute_import, print_function, unicode_literals

from .fields import *


VERSION = (0, 1, 0)

__title__ = 'Enclave'
__version__ = '.'.join((str(i) for i in VERSION)) # str for compatibility with setup.py under Python 3.
__author__ = 'Karan Lyons'
__contact__ = 'karan@karanlyons.com'
__homepage__ = 'https://github.com/karanlyons/django-enclave'
__license__ = 'Apache 2.0'
__copyright__ = 'Copyright 2014 Karan Lyons'
