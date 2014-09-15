#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

from __future__ import division, absolute_import, print_function, unicode_literals

import hmac
import os
from hashlib import sha256

from Crypto.Cipher import AES

from django.db.backends.postgresql_psycopg2.base import DatabaseWrapper

from .exceptions import EnclaveEncryptionError, EnclaveDecryptionError


# We always use Django's Postgres interface as opposed to whichever database
# engine the user is truly using. This allows the encrypted data to be database
# independent, whilst still preserving the ability to do in database encryption
# and decryption in Postgres with pgcrypto.
DUMMY_CONNECTION = DatabaseWrapper({'OPTIONS': {}}, None)


def pad(message):
	'''
	PKCS#7 padding with a block size of 16 bytes.
	
	'''
	
	pad_length = (16 - len(message)) % 16
	
	if pad_length == 0:
		pad_length = 16
	
	return message + (chr(pad_length) * pad_length)


def encrypt(data, secret, field=None):
	'''
	Encrypt data with a given secret, using AES-256 with CBC and
	PKCS#7 Padding, and signed with HMAC-SHA-256.
	
	If given a field, the data will first be conformed to Postgres' db
	representation for that field.
	
	'''
	
	try:
		secret = sha256(secret).digest()
		iv = os.urandom(16)
		data = '\x00' if data is None else '\x01' + data
		
		if field:
			data = field.get_db_prep_save(data, DUMMY_CONNECTION)
		
		message = pad(data)
		
		digest = AES.new(secret, AES.MODE_CBC, iv).encrypt(message)
		payload = iv + digest
		
		return hmac.new(secret, payload, sha256).digest() + payload
	
	except TypeError as e:
		raise EnclaveEncryptionError(e)


def decrypt(digest, secret, field=None):
	'''
	Encrypt's inverse.
	
	'''
	
	try:
		secret = sha256(secret).digest()
		sig, payload = digest[:32], digest[32:]
		
		if not hmac.compare_digest(sig, hmac.new(secret, payload, sha256).digest()):
			raise ValueError('Bad signature.')
		
		else:
			iv, digest = payload[:16], payload[16:]
			
			data = AES.new(secret, AES.MODE_CBC, iv).decrypt(digest)
			
			if data[0] == '\x00':
				return None
			
			else:
				data = data[1:-ord(data[-1])] # Remove padding
				
				return field.to_python(data) if field else data
	
	except (TypeError, ValueError) as e:
		raise e
