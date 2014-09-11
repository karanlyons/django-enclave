#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

from __future__ import division, absolute_import, print_function, unicode_literals


class EnclaveError(Exception):
	'''Unknown Enclave error.'''
	
	def __init__(self, error):
		self.error = error
	
	def __str__(self):
		if self.error:
			return '{} ({}: {})'.format(self.__doc__, self.error.__class__.__name__, self.error)
		
		else:
			return self.__doc__
	
	def __repr__(self):
		return "%s(%r)" % (self.__class__.__name__, repr(self.error))


class EnclaveDecryptionError(EnclaveError):
	'''Could not decrypt data from enclave. The provided secret or AES mode could be incorrect, or the digest corrupted.'''


class EnclaveEncryptionError(EnclaveError):
	'''Could not encrypt data for enclave. The data is most likely unpickleable.'''
