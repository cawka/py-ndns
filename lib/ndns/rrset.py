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

from sqlalchemy import Table, MetaData, Column, ForeignKey, Integer, String, Binary, UniqueConstraint, event
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm.collections import attribute_mapped_collection
from sqlalchemy.orm.collections import collection
from sqlalchemy.orm import deferred

import ndns
from ndns import Base

import dns.message

class RRSet (Base):
    __tablename__ = "rrsets"
    rrs = relationship ("RR", backref="rrset",
                        cascade="all, delete, delete-orphan")

    id = Column (Integer, primary_key = True)
    zone_id = Column (Integer, ForeignKey ("zones.id", onupdate="CASCADE", ondelete="CASCADE"))
    label = Column (String)
    rclass = Column (Integer)
    rtype = Column (Integer)
    _ndndata = Column ("ndndata", Binary)
    
    zone_id_label_rclass_rtype = UniqueConstraint ("zone_id", "label", "rclass", "rtype")

    @property
    def ndndata (self):   
        return pyccn.ContentObject.from_ccnb (self._ndndata)

    @property
    def dns_label (self):
        return dns.name.from_text (self.label).relativize (dns.name.root)

    @property
    def dns_msg (self):
        return dns.message.from_wire (self.ndndata.content)

    def refresh_ndndata (self):
        self._ndndata = ndns.createSignedRRsetData (self).get_ccnb ()

# event.listen (RRSet, 'before_insert', lambda mapper, connection, target: target.refresh_ndndata ())

def check_if_soa (target, value, initiator):
    if target.rtype == dns.rdatatype.SOA:
        target.zone.soa = [target]
event.listen (RRSet.rrs, 'append', check_if_soa)
