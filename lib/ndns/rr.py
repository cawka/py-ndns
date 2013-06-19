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

from sqlalchemy import Table, MetaData, Column, ForeignKey, Integer, String, Binary, UniqueConstraint, event
from sqlalchemy.ext.hybrid import hybrid_property
from ndns import Base
import dns.message

class RR (Base):
    __tablename__ = "rrs"

    id = Column (Integer, primary_key = True)
    rrset_id = Column (Integer, ForeignKey ("rrsets.id", onupdate="CASCADE", ondelete="CASCADE"))
    ttl = Column (Integer)
    _rrdata = Column ("rrdata", Binary)

    @property
    def rrdata (self):
        return self._rrdata

    @property
    def dns_rrdata (self):
        return dns.rdata.from_wire (self.rrset.rclass, self.rrset.rtype, self.rrdata, 0, len (self.rrdata))

    @rrdata.setter
    def rrdata (self, value):
        self._rrdata = buffer (value.to_digestable ())

event.listen (RR, 'before_insert', lambda mapper, connection, target: target.rrset.refresh_ndndata ())
event.listen (RR, 'before_update', lambda mapper, connection, target: target.rrset.refresh_ndndata ())
event.listen (RR, 'before_delete', lambda mapper, connection, target: target.rrset.refresh_ndndata ())
