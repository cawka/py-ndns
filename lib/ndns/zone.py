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

import ndn

from sqlalchemy import Table, MetaData, Column, ForeignKey, Integer, String, Binary, UniqueConstraint
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.hybrid import hybrid_property, hybrid_method

from ndns import Base
from dnsifier import *

import dns.rrset
import dns.message

class Zone (Base):
    __tablename__ = "zones"
    rrsets = relationship ("RRSet", backref="zone", cascade="all, delete, delete-orphan")
    keys = relationship ("Key", backref="zone", cascade="all, delete, delete-orphan", order_by="Key.key_type")
    soa = relationship ("RRSet", #viewonly=True, 
                        primaryjoin = "and_(Zone.id==RRSet.zone_id, RRSet.rclass == %d, RRSet.rtype == %d)" % (dns.rdataclass.IN, dns.rdatatype.SOA))

    id = Column (Integer, primary_key = True)
    _name = Column ("name", Binary, index=True, unique=True)

    default_key_id = Column (Integer)
    default_key = relationship ("Key", 
                                uselist=False, post_update=True,
                                primaryjoin="Zone.default_key_id == Key.id",
                                foreign_keys="Zone.default_key_id",
                                remote_side="Key.id")

    @property
    def name (self):
        return ndn.Name (ccnb_buffer = self._name)

    @property
    def dns_name (self):
        return dns.name.from_text (dnsify (str (self.name)))

    @hybrid_method
    def has_name (self, other):
        return self._name == other.get_ccnb ()

    @name.setter
    def name (self, value):
        self._name = buffer (value.get_ccnb ())
