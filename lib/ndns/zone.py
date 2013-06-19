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

from sqlalchemy import Table, MetaData, Column, ForeignKey, Integer, String, Binary, UniqueConstraint
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.hybrid import hybrid_property, hybrid_method

from ndns import Base

import dns.rrset
import dns.message

class Zone (Base):
    __tablename__ = "zones"
    rrsets = relationship ("RRSet", backref="zone", cascade="all, delete, delete-orphan")
    soa = relationship ("RRSet", #viewonly=True, 
                        primaryjoin = "and_(Zone.id==RRSet.zone_id, RRSet.rclass == %d, RRSet.rtype == %d)" % (dns.rdataclass.IN, dns.rdatatype.SOA))

    id = Column (Integer, primary_key = True)
    _name = Column ("name", Binary, index=True, unique=True)

    @property
    def name (self):
        return pyccn.Name (ccnb_buffer = self._name)

    @hybrid_method
    def has_name (self, other):
        return self._name == other.get_ccnb ()

    @name.setter
    def name (self, value):
        self._name = buffer (value.get_ccnb ())
