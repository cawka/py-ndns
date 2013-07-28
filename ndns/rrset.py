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
    """
    RR set abstraction:
    
    .. code-block:: sql
    
        CREATE TABLE rrsets (
            id INTEGER NOT NULL,
            zone_id INTEGER,
            label VARCHAR,
            rclass INTEGER,
            rtype INTEGER,
            ndndata BLOB,
            PRIMARY KEY (id),
            FOREIGN KEY(zone_id) REFERENCES zones (id) ON DELETE CASCADE ON UPDATE CASCADE
        );

    :ivar rrset: One-to-many relationship to :py:class:`ndns.rr.RR` data
    :ivar zone: Back-reference to the :py:class:`ndns.zone.Zone` to which the key belongs
    """
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
        """
        Get NDN Data packet (:py:class:`ndn.Data`) converted from the stored wire format 
        """
        return ndn.ContentObject.fromWire (self._ndndata)

    @ndndata.setter
    def ndndata (self, value):
        """
        Save Data packet in the database in its wire format
        """
        self._ndndata = value.toWire ()

    @property
    def dns_label (self):
        """
        Get DNS label of the RR set (relatively to the zone)
        """
        return dns.name.from_text (self.label).relativize (dns.name.root)

    @property
    def dns_msg (self):
        """
        Get DNS representation (:py:class:`dns.message.Message`) of the stored RR set
        """
        return dns.message.from_wire (self.ndndata.content)

    def refresh_ndndata (self, session, key):
        """
        Refresh (re-sign) NDN Data packet associated with RR set

        :param session: Dictionary containing configuration information (e.g., keydir)
        :type session: dict
        :param key: :py:class:`ndns.key.Key` object that should be used for sigining the Data packet
        :type key: :py:class:`ndns.key.Key`
        """
        self._ndndata = ndns.createSignedRRsetData (session, self, key).toWire ()


def _check_if_soa (target, value, initiator):
    if target.rtype == dns.rdatatype.SOA:
        target.zone.soa = [target]
event.listen (RRSet.rrs, 'append', _check_if_soa)
