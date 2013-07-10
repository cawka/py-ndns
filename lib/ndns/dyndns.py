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
from key import *
from dnsifier import *
from policy.identity import *

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

def session (path):
    zonedb = "%s/.dyndns.db" % path
    keydir = path

    db = create_engine ('sqlite:///%s' % zonedb)
    Base.metadata.create_all (db)
    
    sm = sessionmaker (bind = db)
    session = sm ()
    session.keydir = keydir
    return session

