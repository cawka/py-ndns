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
from sqlalchemy.ext.hybrid import hybrid_property, hybrid_method
from ndns import Base
import dns.message

class RR (Base):
    """
    Resource record abstraction:
    
    .. code-block:: sql
    
        CREATE TABLE rrs (
            id INTEGER NOT NULL,
            rrset_id INTEGER,
            ttl INTEGER,
            rrdata BLOB,
            PRIMARY KEY (id),
            FOREIGN KEY(rrset_id) REFERENCES rrsets (id) ON DELETE CASCADE ON UPDATE CASCADE
        );

    :ivar zone: Back-reference to the :py:class:`ndns.rrset.RRSet` to which the RR belongs
    :type zone: :py:class:`ndns.rrset.RRSet`
    """
    __tablename__ = "rrs"

    id = Column (Integer, primary_key = True)
    rrset_id = Column (Integer, ForeignKey ("rrsets.id", onupdate="CASCADE", ondelete="CASCADE"))
    ttl = Column (Integer)
    _rrdata = Column ("rrdata", Binary)

    @property
    def rrdata (self):
        """Get wire-formatted RDATA"""
        return self._rrdata

    @property
    def dns_rrdata (self):
        """Get :py:class:`dns.rdata.Rdata` object converted from the stored wire-formatted RDATA"""
        return dns.rdata.from_wire (self.rrset.rclass, self.rrset.rtype, self.rrdata, 0, len (self.rrdata))

    @rrdata.setter
    def rrdata (self, value):
        """
        Convert value to a wire-format and save it in the database

        :param value: :py:class:`dns.rdata.Rdata` object
        :type value: :py:class:`dns.rdata.Rdata`
        """
        self._rrdata = buffer (value.to_digestable (origin = self.rrset.zone.dns_name))

    @hybrid_method
    def has_rrdata (self, other, origin):
        """Facilitate SQL comparison with another RDATA in wire format"""
        return self._rrdata == buffer (other.to_digestable (origin = origin))
