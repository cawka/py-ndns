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

# make sure modules from lib/ are loaded
import sys; sys.path = ["%s/../lib" % sys.path[0]] + sys.path

import argparse, time, logging, logging.handlers
import ndns
from ndns.policy.identity import *
import ndn

_LOG = logging.getLogger ()
_LOG.setLevel (logging.DEBUG)

_handler = logging.StreamHandler (sys.stderr)
_handler.setLevel (logging.DEBUG)
_handler.setFormatter (logging.Formatter('%(asctime)s %(name)s [%(levelname)s]  %(message)s', '%H:%M:%S'))
_LOG.addHandler (_handler)

TrustPolicy = IdentityPolicy (
    anchors = [[pyccn.Name ("/ndn/keys/ucla.edu/alex/%C1.M.K%00F%8D%E9%C3%EE4%7F%C1Mjqro%C6L%8DGV%91%90%03%24%ECt%95n%F3%9E%A6i%F1%C9"), 
                pyccn.Name ("/"),
                pyccn.Key.createFromPEM (public = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDSPdPM7+DjDcUGHtwEDmkq4kO5
tEUI05w5gR4JC1UiZxS0ckMWSLRPWXozHrpJsjNzDeI6OiQrXzup1tF2IN+Xtdr+
Pr3CwyBRloTJJbm5kf+pGuJh4fE9Qk0i/fS9Xs6gFup3oPnr+wFFjJObnRTrUsaM
8TQokOLYZFsatsZOvwIDAQAB
-----END PUBLIC KEY-----""")
                ]],
    rules = [["^((/[^/]+)*)/DNS((/[^/]+)*)/[^/]+/NDNCERT$", "\\1\\3"]]
    )

if( __name__ == '__main__' ):

    ndn = ndn.Face ()
    ndn.defer_verification (True)
    co = ndn.get (pyccn.Name ("/ndn/DNS/test/A"))

    print TrustPolicy.verify (co)
