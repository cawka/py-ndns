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
from key import *
from dnsifier import *
from policy.identity import *
import query

import dns.rdataclass
import dns.rdatatype
import dns.rdata
import dns.rrset
import dns.zone

TrustPolicy = IdentityPolicy (
    anchors = [[ndn.Name ("/ndn/keys/ucla.edu/alex/%C1.M.K%00F%8D%E9%C3%EE4%7F%C1Mjqro%C6L%8DGV%91%90%03%24%ECt%95n%F3%9E%A6i%F1%C9"), 
                ndn.Name ("/"),
                ndn.Key.createFromPEM (public = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDSPdPM7+DjDcUGHtwEDmkq4kO5
tEUI05w5gR4JC1UiZxS0ckMWSLRPWXozHrpJsjNzDeI6OiQrXzup1tF2IN+Xtdr+
Pr3CwyBRloTJJbm5kf+pGuJh4fE9Qk0i/fS9Xs6gFup3oPnr+wFFjJObnRTrUsaM
8TQokOLYZFsatsZOvwIDAQAB
-----END PUBLIC KEY-----""")
                ]],
    rules = [["^((/[^/]+)*)/DNS((/[^/]+)*)/[^/]+/NDNCERT$", "\\1\\3", "^((/[^/]+)*)/DNS((/[^/]+)*)$", "\\1\\3"],
             ["^((/[^/]+)*)/DNS((/[^/]+)*)/[^/]+/NDNCERT$", "\\1\\3", "^((/[^/]+)*)/([^/\.]+)\.([^/\.]+)/DNS((/[^/]+)*)$", "\\1/\\4/\\3\\5"],
             ["^((/[^/]+)*)/DNS((/[^/]+)*)/[^/]+/NDNCERT$", "\\1\\3", "(.*)", "\\1"]]
    )

CachingQueryObj = query.CachingQuery ()

def ndns_session (config = "etc/ndns.conf"):
    conf = iscpy.ParseISCString (open (config).read ())
    zonedb = conf['options']['zonedb'].strip ("\"'")
    keydir = conf['options']['keydir'].strip ("\"'")
    scopes = [ndn.Name (scope.strip ("\"'")) for scope in conf['options']['scopes'].keys ()]

    db = create_engine ('sqlite:///%s' % zonedb)
    # db.echo = True
    
    Base.metadata.create_all (db)
    
    sm = sessionmaker (bind = db)
    session = sm ()
    session.keydir = keydir
    session.scopes = scopes
    return session

def createSignedData (session, name, content, freshness, key, type = ndn.CONTENT_DATA):
    signingKey = key.private_key (session.keydir)
    signedInfo = ndn.SignedInfo (key_digest = signingKey.publicKeyID, key_locator = key.key_locator, 
                                   freshness = freshness,
                                   type = type)
    # , py_timestamp = time.mktime (time.gmtime()))

    co = ndn.ContentObject (name = name, signed_info = signedInfo, content = content)

    co.sign (signingKey)
    return co

def createSignedRRsetData (session, rrset, key, version = None):
    label = dns.name.from_text (rrset.label).relativize (dns.name.root)

    rdclass = rrset.rclass
    rdtype = rrset.rtype

    zone_name = rrset.zone.name
    zone_origin = dns.name.from_text (dnsify (str (zone_name)))

    ttl = -1
    if rdtype == dns.rdatatype.NDNCERT:
        # Ok. Doing some cheat, treating NDNCERT data completely differently
        content = rrset.rrs[0].dns_rrdata.cert
        if (rrset.rrs[0].ttl < ttl):
            ttl = rrset.rrs[0].ttl
    else:
        newrrset = dns.rrset.RRset (label, rdclass, rdtype)
        ttl = -1
        for rr in rrset.rrs:
            newrrset.add (ttl = rr.ttl, rd = dns.rdata.from_wire (rdclass, rdtype, rr.rrdata, 0, len (rr.rrdata)))
            if (ttl == -1 or rr.ttl < ttl):
                ttl = rr.ttl
    
        msg = dns.message.Message (id=0)
        msg.answer.append (newrrset)
    
        content = msg.to_wire (origin = zone_origin)
    
    if ttl <= -1:
        if rrset.zone and rrset.zone.soa and rrset.zone.soa[0]:
            ttl = rrset.zone.soa[0].rrs[0].ttl
        else:
            ttl = 3600
    
    rrset_name = ndn.Name (zone_name)
    rrset_name = rrset_name.append ("DNS")
    if (len (label) > 0):
        ndn_label = ndnify (label.to_text ())
        for label in ndn_label:
            rrset_name = rrset_name.append (label)
    rrset_name = rrset_name.append (dns.rdatatype.to_text (rdtype))
    rrset_name = rrset_name.appendVersion (version)

    return createSignedData (session, rrset_name, content, ttl, key, type = ndn.CONTENT_DATA if rdtype != dns.rdatatype.NDNCERT else ndn.CONTENT_KEY)    

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

    return rrset
