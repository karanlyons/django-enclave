#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

from __future__ import division, absolute_import, print_function, unicode_literals

import hmac
import os
from hashlib import sha256

import psycopg2
from Crypto.Cipher import AES

from django.conf import settings

from .exceptions import EnclaveEncryptionError, EnclaveDecryptionError


ENCLAVE_KEY = bytes(sha256(bytes(getattr(settings, 'ENCLAVE_KEY', settings.SECRET_KEY))).digest())
MAPPING = {
	'AutoField': 'serial',
	'BinaryField': psycopg2.BINARY,
	'BooleanField': psycopg2.extensions.BOOLEAN,
	'CharField': psycopg2.STRING,
	'CommaSeparatedIntegerField': psycopg2.STRING,
	'DateField': psycopg2.extensions.DATE,
	'DateTimeField': psycopg2.DATETIME,
	'DecimalField': psycopg2.extensions.DECIMAL,
	'FileField': psycopg2.STRING,
	'FilePathField': psycopg2.STRING,
	'FloatField': psycopg2.extensions.FLOAT,
	'IntegerField': psycopg2.extensions.INTEGER,
	'BigIntegerField': psycopg2.extensions.LONGINTEGER,
	'IPAddressField': 'inet',
	'GenericIPAddressField': 'inet',
	'NullBooleanField': psycopg2.extensions.BOOLEAN,
	'OneToOneField': psycopg2.extensions.INTEGER,
	'PositiveIntegerField': psycopg2.extensions.INTEGER,
	'PositiveSmallIntegerField': psycopg2.extensions.INTEGER,
	'SlugField': psycopg2.STRING,
	'SmallIntegerField': psycopg2.extensions.INTEGER,
	'TextField': psycopg2.STRING,
	'TimeField': psycopg2.extensions.TIME,
}
DUMMY_CURSOR = psycopg2.extensions.cursor(psycopg2.extensions.connection(''), None)


def pad(message):
	pad_length = (32 - (len(message) + 2)) % 32
	
	return bytes('{0:02d}'.format(pad_length) + message + '0' * pad_length)


def encrypt(data, secret):
	try:
		secret = bytes(sha256(secret).digest())
		iv = os.urandom(16)
		null_flag = bytes('1' if data is None else '0')
		
		data = psycopg2.extensions.adapt(data).getquoted()
		
		if '::' in data:
			data = data.split('::')[0]
		
		if data[0] == "'" and data[-1] == "'":
			data = data[1:-1]
		
		message = pad(bytes(null_flag + data))
		
		digest = AES.new(secret, AES.MODE_CBC, iv).encrypt(message)
		payload = bytes(iv + digest)
		
		return bytes(hmac.new(ENCLAVE_KEY, payload, sha256).digest() + payload)
	
	except TypeError as e:
		raise EnclaveEncryptionError(e)


def decrypt(digest, secret, internal_type):
	try:
		secret = bytes(sha256(secret).digest())
		sig, payload = digest[:32], digest[32:]
		
		if sig != bytes(hmac.new(ENCLAVE_KEY, payload, sha256).digest()):
			raise ValueError('Bad signature.')
		
		else:
			iv, digest = payload[:16], payload[16:]
			
			data = AES.new(secret, AES.MODE_CBC, iv).decrypt(digest)
			data = data[2:len(data) - int(data[0:2])]
			
			if data[0] == '1':
				return None
			
			else:
				return MAPPING[internal_type](data[1::], psycopg2.extensions.cursor(psycopg2.extensions.connection(''), None))
	
	except (TypeError, ValueError) as e:
		raise EnclaveDecryptionError(e)
