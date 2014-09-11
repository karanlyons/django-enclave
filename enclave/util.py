#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

from __future__ import division, absolute_import, print_function, unicode_literals

import cPickle as pickle
import hmac
import os
from hashlib import sha256

from Crypto.Cipher import AES

from django.conf import settings

from .exceptions import EnclaveEncryptionError, EnclaveDecryptionError


BLOCK_SIZE = 32


def pad(message, block_size=BLOCK_SIZE):
	pad_length = (block_size - (len(message) + 2)) % block_size
	
	return bytes('{0:02d}'.format(pad_length)) + message + bytes('\x00') * pad_length


def encrypt(data, secret, mode=AES.MODE_CBC):
	try:
		key = sha256(secret).digest()
		iv = os.urandom(16)
		message = pad(pickle.dumps(data))
		
		digest = AES.new(key, mode, iv).encrypt(message)
		payload = iv + digest
		
		return hmac.new(str(settings.SECRET_KEY), str(payload), sha256).digest() + payload
	
	except (TypeError, pickle.PicklingError) as e:
		raise EnclaveEncryptionError(e)


def decrypt(digest, secret, mode=AES.MODE_CBC):
	try:
		key = sha256(secret).digest()
		sig, payload = digest[:32], digest[32:]
		
		if sig != hmac.new(str(settings.SECRET_KEY), str(payload), sha256).digest():
			raise ValueError('Bad signature.')
		
		else:
			iv, digest = payload[:16], payload[16:]
			
			data = AES.new(key, mode, iv).decrypt(digest)
			
			return pickle.loads(data[2:len(data) - int(data[0:2])])
	
	except (TypeError, ValueError, pickle.UnpicklingError) as e:
		raise EnclaveDecryptionError(e)
