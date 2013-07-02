#!/usr/bin/env python
# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
# 
# Copyright (c) 2013, Regents of the University of California
#                     Alexander Afanasyev
# 
# BSD license, See the doc/LICENSE file for more information
# 
# Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
# 

import pyccn

from sqlalchemy import Table, MetaData, Column, ForeignKey, Integer, Binary, Enum, UniqueConstraint
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.hybrid import hybrid_property, hybrid_method
import os

from ndns import Base
from dnsifier import *

class KeyException (Exception):
    pass

class Key (Base):
    __tablename__ = "keys"

    id = Column (Integer, primary_key = True)
    zone_id = Column (Integer, ForeignKey ("zones.id", onupdate="CASCADE", ondelete="CASCADE"), index=True)
    _name = Column ("name", Binary, index=True, unique=True)
    _parent_zone = Column ("parent_zone", Binary) # only makes sense for KSKs

    key_type = Column (Enum ("KSK", "ZKS", "DZSK"), nullable=False, default="ZSK")
    # DZSK: dynamic-zone signing key

    rrset_id = Column (Integer)
    rrset = relationship ("RRSet", 
                          uselist=False, post_update=True,
                          primaryjoin="Key.rrset_id == RRSet.id",
                          foreign_keys="Key.rrset_id", 
                          remote_side="RRSet.id")

    _key = None

    @property
    def name (self):
        return pyccn.Name (ccnb_buffer = self._name)

    @property
    def parent_zone (self):
        if self._parent_zone:
            return pyccn.Name (ccnb_buffer = self._parent_zone)
        else:
            return None

    @property
    def label (self):
        name = self.name
        if name[:len(self.zone.name)] == self.zone.name:
            return dnsify (str (pyccn.Name (name[len(self.zone.name) + 1 : -1])))
        else:
            raise KeyException ("Key does not belong to the zone (KSK should be stored in the parent zone!)")

    @property
    def ndn_label (self):
        name = self.name
        if name[:len(self.zone.name)] == self.zone.name:
            return pyccn.Name (name[len(self.zone.name) + 1 : -1])
        else:
            raise KeyException ("Key does not belong to the zone (KSK should be stored in the parent zone!)")

    @property
    def parent_label (self):
        if self.key_type != "KSK":
            raise KeyException ("Key.parent_label makes sense only for KSK keys")

        if self.parent_zone is None:
            raise KeyException ("Parent zone is not set (key is stored outside NDNS)")

        name = self.name
        if name[:len(self.parent_zone)] == self.parent_zone:
            return dnsify (str (pyccn.Name (name[len(self.parent_zone) + 1 : -1])))
        else:
            raise KeyException ("Key does not belong to the parent zone")
        
    @property
    def local_key_id (self):
        return dnsify (str (pyccn.Name (self.name[:-1])), invert = True)

    @hybrid_method
    def has_name (self, other):
        return self._name == other.get_ccnb ()

    @name.setter
    def name (self, value):
        self._name = buffer (value.get_ccnb ())

    @parent_zone.setter
    def parent_zone (self, value):
        self._parent_zone = buffer (value.get_ccnb ())

    def generate (self, keydir, password = None):
        '''Generate key pair on disk'''

        self._key = pyccn.Key ()
        self._key.generateRSA (2048 if self.key_type == "KSK" else 1024)

        if not os.path.exists (keydir):
            os.makedirs (keydir)

        local_key_id = self.local_key_id

        if os.path.exists ("%s/%s.pub" % (keydir, local_key_id)):
            raise KeyException ("Key already exists (%s/%s.pub), to re-generate the key, delete it manually" % (keydir, local_key_id))

        if os.path.exists ("%s/%s.pri" % (keydir, local_key_id)):
            raise KeyException ("Key already exists (%s/%s.pri), to re-generate the key, delete it manually" % (keydir, local_key_id))

        self._key.publicToPEM ("%s/%s.pub" % (keydir, local_key_id))
        self._key.privateToPEM ("%s/%s.pri" % (keydir, local_key_id), password = password)

    def erase (self, keydir):
        if not os.path.exists (keydir):
            return

        try:
            os.unlink ("%s/%s.pub" % (keydir, self.local_key_id))
            os.unlink ("%s/%s.pri" % (keydir, self.local_key_id))
        except:
            pass

    def load_default_key (self):
        self._key = pyccn.Key.getDefaultKey ()
        self.name = pyccn.KeyLocator.getDefaultKeyLocator ().keyName
        
    def load_from_pubkey (self, pubkey):
        self._key = pyccn.Key ()
        self._key.fromPEM (pubkey)

    @property
    def key_locator (self):
        return pyccn.KeyLocator (self.name)

    def private_key (self, keydir, password = None):
        if not self._key:
            self._key = pyccn.Key ()
            self._key.fromPEM ("%s/%s.pri" % (keydir, self.local_key_id), password = password)

        return self._key

    def public_key (self, keydir):
        if not self._key:
            key = pyccn.Key ()
            key.fromPEM ("%s/%s.pub" % (keydir, self.local_key_id))
            return key

        return self._key
