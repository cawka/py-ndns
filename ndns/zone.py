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
    """
    Zone abstraction:

    .. code-block:: sql
    
        CREATE TABLE zones (
        	id INTEGER NOT NULL,
        	name BLOB,
        	default_key_id INTEGER,
        	PRIMARY KEY (id)
        );
        CREATE UNIQUE INDEX ix_zones_name ON zones (name);

    :ivar rrsets: One to many relationship to :py:class:`ndns.rrset.RRSet`
    :ivar soa:    One-to-one map (shortcut) to SOA :py:class:`ndns.rrset.RRSet` of the zone
    :ivar keys:   One to many relationship to :py:class:`ndns.key.Key`
    :ivar default_key: One-to-one map to default :py:class:`ndns.key.Key` for the zone
    """

    __tablename__ = "zones"
    
    id = Column (Integer, index=True, primary_key = True)
    _name = Column ("name", Binary, index=True)
    # , unique=True)
    default_key_id = Column (Integer)

    rrsets = relationship ("RRSet", backref="zone", cascade="all, delete, delete-orphan") #: hello2
    soa = relationship ("RRSet", #viewonly=True, 
                        primaryjoin = "and_(Zone.id==RRSet.zone_id, RRSet.rclass == %d, RRSet.rtype == %d)" % (dns.rdataclass.IN, dns.rdatatype.SOA))

    keys = relationship ("Key", backref="zone", cascade="all, delete, delete-orphan", order_by="Key.key_type")
    default_key = relationship ("Key", 
                                uselist=False, post_update=True,
                                primaryjoin="Zone.default_key_id == Key.id",
                                foreign_keys="Zone.default_key_id",
                                remote_side="Key.id")

    @property
    def name (self):
        """Convert internal wire representation of zone name to :py:class:`ndn.Name` object"""
        return ndn.Name.fromWire (self._name)

    @property
    def dns_name (self):
        """Convert internal wire representation of zone name to DNS name (:py:class:`dns.name.Name` object)"""
        return dns.name.from_text (dnsify (str (self.name)))

    @hybrid_method
    def has_name (self, other):
        """Facilitate SQL comparison with another zone name in wire format"""
        return self._name == other.toWire ()

    @name.setter
    def name (self, value):
        """Set zone name to the wire representation of the value

        :type  :value: ndn.Name
        :param :value: zone name
        """
        self._name = buffer (value.toWire ())
