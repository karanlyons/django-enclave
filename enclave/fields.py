#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

from __future__ import division, absolute_import, print_function, unicode_literals

import os

from django.db import models
from django.conf import settings
from django.core.cache import caches
from django.utils import six
from django.utils.encoding import force_bytes

from . import util, exceptions


__all__ = ['EnclaveKeyField', 'EnclaveDataField', 'EncryptedData']


ENCLAVE_KEY = getattr(settings, 'ENCLAVE_KEY', settings.SECRET_KEY)


class EncryptedData(object):
	def __init__(self, buffer):
		self.buffer = buffer
	
	def __unicode__(self):
		return "[Encrypted Data]"
	
	def __str__(self):
		return self.__unicode__()
	
	def __repr__(self):
		return "EncryptedData({})".format(repr(self.buffer))


class EnclaveKey(object):
	def __init__(self, owner, instance, field):
		self.owner = owner
		self.instance = instance
		self.field = field
		self.cache_key = ':'.join(('enclave', self.instance._meta.app_label, self.instance._meta.model_name, unicode(self.instance.pk), self.field.name))
	
	@property
	def is_unlocked(self):
		return bool(self.field.cache.get(self.cache_key))
	
	@property
	def is_locked(self):
		return not self.is_unlocked
	
	def lock(self, raw_password=None):
		if not self.instance:
			raise RuntimeError('Can\'t lock {} without {} instance.'.format(self.field.name, self.owner.__name__))
		
		else:
			if raw_password:
				enclave_key = self.field.cache.get(self.cache_key)
				
				if enclave_key:
					raw_enclave_key = util.decrypt(enclave_key, ENCLAVE_KEY, self.field)
					setattr(self.instance, self.field.name, util.encrypt(raw_enclave_key, raw_password))
					self.instance.save(update_fields=[self.field.name])
				
				else:
					raise RuntimeError('Can\'t lock {} with new password: already locked.'.format(self.field.name))
			
			self.field.cache.delete(self.cache_key)
			
			return self.is_locked
	
	def unlock(self, raw_password):
		if not self.instance:
			raise RuntimeError('Can\'t unlock {} without {} instance.'.format(self.field.name, self.owner.__name__))
		
		else:
			if self.instance.__dict__[self.field.name] is None:
				setattr(self.instance, self.field.name, util.encrypt(os.urandom(512), raw_password))
				self.instance.save(update_fields=[self.field.name])
			
			try:
				raw_enclave_key = util.decrypt(self.field.to_python(self.instance.__dict__[self.field.name]), raw_password, self.field)
				self.field.cache.set(self.cache_key, util.encrypt(raw_enclave_key, ENCLAVE_KEY))
			
			except exceptions.EnclaveDecryptionError:
				self.field.cache.delete(self.cache_key)
			
			return self.is_unlocked


class EnclaveKeyDescriptor(object):
	def __init__(self, field):
		self.field = field
	
	def __get__(self, instance=None, owner=None):
		return EnclaveKey(owner, instance, self.field)
	
	def __set__(self, instance, value):
		instance.__dict__[self.field.name] = value


class EnclaveKeyField(models.BinaryField):
	description = "Encryption key"
	descriptor_class = EnclaveKeyDescriptor
	
	def __init__(self, *args, **kwargs):
		self.max_length = None
		self.cache = caches[kwargs.get('cache', 'default')]
		
		super(EnclaveKeyField, self).__init__(*args, **kwargs)
	
	def pre_save(self, model_instance, add):
		return model_instance.__dict__[self.attname]
	
	def contribute_to_class(self, cls, name, **kwargs):
		super(EnclaveKeyField, self).contribute_to_class(cls, name, **kwargs)
		
		if not getattr(cls._meta, 'has_enclave_key_field', False):
			cls._meta.has_enclave_key_field = True
			cls._meta.enclave_key_field = self.attname
		
		setattr(cls, self.name, self.descriptor_class(self))


class EnclaveFieldDescriptor(object):
	def __init__(self, field):
		self.field = field
	
	def get_raw_enclave_key(self, instance):
		try:
			name_map = instance._meta._name_map
		
		except AttributeError:
			name_map = instance._meta.init_name_map()
		
		relation_field = name_map[self.field.relation][0]
		related_model = relation_field.rel.to
		
		if self.field.key_field is None:
			self.field.key_field = related_model._meta.enclave_key_field
		
		cache_key = ':'.join(('enclave', related_model._meta.app_label, related_model._meta.model_name, unicode(getattr(instance, relation_field.attname)), self.field.key_field))
		
		enclave_key = self.field.cache.get(cache_key)
		
		return util.decrypt(enclave_key, ENCLAVE_KEY, self.field) if enclave_key else None
	
	def __get__(self, instance=None, owner=None):
		try:
			return self.field.to_python(util.decrypt(instance.__dict__[self.field.name], self.get_raw_enclave_key(instance), self.field), saving=False)
		
		except:
			return EncryptedData(instance.__dict__[self.field.name])
	
	def __set__(self, instance, value):
		if isinstance(value, buffer):
			instance.__dict__[self.field.name] = value
		
		else:
			raw_enclave_key = self.get_raw_enclave_key(instance)
			
			if raw_enclave_key is None:
				raise RuntimeError('Can\'t set {} with locked enclave.'.format(self.field.name))
			
			else:
				instance.__dict__[self.field.name] = util.encrypt(value, raw_enclave_key)


class EnclaveFieldMixin(object):
	description = "Encrypted field"
	descriptor_class = EnclaveFieldDescriptor
	
	def __new__(cls, *args, **kwargs):
		instance = super(EnclaveFieldMixin, cls).__new__(cls, *args, **kwargs)
		instance.description = "Encrypted {}".format(super(EnclaveFieldMixin, cls).description.lower())
		
		return instance
	
	def __init__(self, *args, **kwargs):
		self.cache = caches[kwargs.pop('cache', 'default')]
		self.relation = kwargs.pop('relation', None)
		self.key_field = kwargs.pop('key_field', None)
		
		super(EnclaveFieldMixin, self).__init__(*args, **kwargs)
	
	def deconstruct(self):
		name, path, args, kwargs = super(EnclaveFieldMixin, self).deconstruct()
		return(name, path, args, kwargs)
	
	def get_internal_type(self):
		return "BinaryField"
	
	def get_default(self):
		if self.has_default() and not callable(self.default):
			return self.default
		
		default = super(EnclaveFieldMixin, self).get_default()
		
		if default == '':
			return b''
		
		return default
	
	def get_db_prep_value(self, value, connection, prepared=False):
		value = super(EnclaveFieldMixin, self).get_db_prep_value(value, connection, prepared)
		
		if value is not None:
			return connection.Database.Binary(value)
		
		return value
	
	def get_db_prep_save(self, value, connection):
		return self.get_db_prep_value(value, connection=connection, prepared=False)
	
	def value_to_string(self, obj):
		return force_bytes(self._get_val_from_obj(obj))
	
	def to_python(self, value, saving=True):
		if saving:
			return value
		
		elif isinstance(value, six.text_type):
			return super(EnclaveFieldMixin, self).to_python(six.memoryview(force_bytes(value)))
		
		else:
			return super(EnclaveFieldMixin, self).to_python(value)
	
	def pre_save(self, model_instance, add):
		return model_instance.__dict__[self.attname]
	
	def contribute_to_class(self, cls, name, **kwargs):
		super(EnclaveFieldMixin, self).contribute_to_class(cls, name, **kwargs)
		
		if not self.relation:
			self.relation = cls
		
		setattr(cls, self.name, self.descriptor_class(self))


class DataField(models.Field):
	description = "pickled data"

EnclaveDataField = type(str('EnclaveDataField'), (EnclaveFieldMixin, DataField, object), {})


for field in (getattr(models, s) for s in dir(models) if s.endswith('Field') and s not in ('OneToOneField', 'ManyToManyField', 'Field')):
	if not hasattr(field, 'descriptor_class'):
		enclave_field_name = str('Enclave{}'.format(field.__name__))
		globals()[enclave_field_name] = type(enclave_field_name, (EnclaveFieldMixin, field, object), {})
		__all__.append(enclave_field_name)

__all__ = tuple(__all__)
