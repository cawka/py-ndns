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

import iscpy
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

Base = declarative_base ()
from zone import *
from rrset import *
from rr import *
from dnsifier import *

import dns.rdataclass
import dns.rdatatype
import dns.rdata
import dns.rrset
import dns.zone

def ndns_session (config = "etc/ndns.conf"):
    conf = iscpy.ParseISCString (open (config).read ())
    zonedb = conf['options']['zonedb'].strip ("\"'");
    db = create_engine ('sqlite:///%s' % zonedb)
    # db.echo = True
    
    Base.metadata.create_all (db)
    
    sm = sessionmaker (bind = db)
    return sm ()

def createSignedRRsetData (rrset):
    label = dns.name.from_text (rrset.label).relativize (dns.name.root)

    rdclass = rrset.rclass
    rdtype = rrset.rtype

    soa = rrset.zone.soa[0]

    zone_name = rrset.zone.name
    zone_origin = dns.name.from_text (dnsify (str (zone_name)))

    key = pyccn.Key.getDefaultKey ()
    keyLocator = pyccn.KeyLocator.getDefaultKeyLocator ()

    newrrset = dns.rrset.RRset (label, rdclass, rdtype)
    ttl = -1
    for rr in rrset.rrs:
        newrrset.add (ttl = rr.ttl, rd = dns.rdata.from_wire (rdclass, rdtype, rr.rrdata, 0, len (rr.rrdata)))
        if (ttl == -1 or rr.ttl < ttl):
            ttl = rr.ttl

    if ttl <= 1:
        ttl = soa.rrs[0].ttl

    rrset_name = pyccn.Name (zone_name)
    rrset_name = rrset_name.append ("dns")
    if (len (label) > 0):
        rrset_name = rrset_name.append (label.to_text ())
    rrset_name = rrset_name.append (dns.rdatatype.to_text (rdtype))
    rrset_name = rrset_name.appendVersion ()
    
    signedInfo = pyccn.SignedInfo (key_digest = key.publicKeyID, key_locator = keyLocator, 
                                   freshness = ttl)
    # , py_timestamp = time.mktime (time.gmtime()))

    msg = dns.message.Message (id=0)
    msg.answer.append (newrrset)

    co = pyccn.ContentObject (name = rrset_name, signed_info = signedInfo, content = msg.to_wire (origin = zone_origin))

    co.sign (key)
    return co

def add_rr (session, zone, origin, name, ttl, rdata):
    # print "Create record: '%s %s %d %s'" % (name, dns.rdatatype.to_text (rdata.rdtype), ttl, rdata.to_text ())

    rrset = session.query (ndns.RRSet).\
        with_parent (zone).\
        filter_by (label = name.to_text (), rclass = rdata.rdclass, rtype = rdata.rdtype).\
        first ()
    
    if not rrset:
        rrset = ndns.RRSet (label = name.to_text (), rclass = rdata.rdclass, rtype = rdata.rdtype)
        zone.rrsets.append (rrset)
    else:        
        if (dns.rdatatype.is_singleton (rdata.rdtype)):
            rrset.rrs = []
        else:
            # Do some checking that were previously done elsewhere
            for old_rdata in session.query (ndns.RR).with_parent (rrset).filter (ndns.RR.has_rrdata (rdata, origin)):
                session.delete (old_rdata)

    rr = ndns.RR (ttl = ttl)
    rrset.rrs.append (rr)  
    rr.rrdata = rdata

    rrset.refresh_ndndata ()
