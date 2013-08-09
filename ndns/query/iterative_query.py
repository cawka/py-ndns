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

from ndns.dnsifier import *

import dns.rdataclass
import dns.rdatatype
import dns.rdata
import dns.rrset
import dns.message
import dns.rdtypes.IN.NDNCERT
import ndns
import re
import random
import logging
import ndn
import time
import functools

_LOG = logging.getLogger ("ndns.query.Iterative")

class IterativeQuery:
    def __init__ (self, face, 
                  onResult, onError, 
                  name, rrtype = dns.rdatatype.FH, parse_dns = True):
        self.face = face
        self.onResult = onResult
        self.onError = onError
        self.name = name
        self.rrtype = rrtype
        self.parse_dns = parse_dns

        self.zone = ndn.Name ()
        self.hint = None
        self.i = 0
        self.label_real = ndn.Name ()
        self.label_logical = ndn.Name ()
        
    @staticmethod
    def expressQuery (face, 
                      onResult, onError, 
                      name, rrtype = dns.rdatatype.FH, parse_dns = True):
        
        if rrtype is None:
            rrtype = dns.rdatatype.FH

        if isinstance (rrtype, str):
            rrtype = dns.rdatatype.from_text (rrtype)

        _LOG.debug ("expressQuery: name: %s, type: %s" % (name, dns.rdatatype.to_text (rrtype)))

        query = IterativeQuery (face, onResult, onError, name, rrtype, parse_dns)
        query._getMostSpecificNsAnswer (tryEmptyLabel = False)

    @staticmethod
    def expressQueryForZoneFh (face, onFhResult, onError, name):

        _LOG.debug ("expressQueryForZoneFh: zone: %s" % name)
        
        query = IterativeQuery (face, onFhResult, onError, name, None, False)
        query._getMostSpecificNsAnswer (tryEmptyLabel = False)
        
    def _getMostSpecificNsAnswer (self, tryEmptyLabel = False):
        _LOG.debug ('_getMostSpecificNsAnswer [in %s for %s NS]' % (self.zone, self.label_logical))
        if self.i < len (self.name):
            if not tryEmptyLabel:
                component = self.name[self.i]
                self.i += 1

                self.label_logical = ndn.Name ().append (ndnify (str(component)))
                self.label_real    = ndn.Name ().append (component)

            ndns.CachingQueryObj.expressQueryFor(self.face,
                                                 self._onMostSpecificNsAnswer, self.onError,
                                                 self.zone, self.hint, self.label_logical, dns.rdatatype.NS, True) #, verify = False)
        else:
            self._onNoMoreNsDelegation ()


    def _onMostSpecificNsAnswer (self, result, msg):
        if (len(msg.answer)==0 and len(msg.authority)==1 and msg.authority[0].rdtype == dns.rdatatype.NDNAUTH):
            self.getMostSpecificAnswer (tryEmptyLabel = False)

        if (len(msg.answer) > 0 and msg.answer[0].rdtype == dns.rdatatype.NS):
            self._onNsResult (result, msg)
        else:
            _LOG.debug ('Got %s instead of NS' % dns.rdatatype.to_text (msg.answer[0].rdtype))
            self._onNoMoreNsDelegation ()

    def _onNsResult (self, ns_result, ns_msg):
        ns_rrdata = random.choice (ns_msg.answer[0].items)

        # A couple of cheats, to handle names like "/ndn/ucla.edu/irl"

        # ns_target = ndnify (ns_rrdata.target.relativize (dns.name.root).to_text ())
        dns_zone = dns.name.from_text (dnsify (str(self.zone)))
        dns_ns_target = ns_rrdata.target
        
        if dns_ns_target.is_subdomain (dns_zone):
            ns_label = ndn.Name (ndnify (dns_ns_target.relativize (dns_zone).to_text ()))
            ndns.CachingQueryObj.expressQueryFor (self.face, 
                                                  self._onFhResult, self.onError, 
                                                  self.zone, self.hint, ns_label, dns.rdatatype.FH, True) #, verify = False)
        else:
            # ns_target = ndn.Name (ndnify (dns_ns_target.relativize (dns.name.root).to_text ()))
            # IterativeQuery.expressQuery (self.face, self._onFhResult, self.onError, 
            #                              ns_target, dns.rdatatype.FH, True)
            
            self.onError ("NS record pointing outside the domain structure is currently not supported")
            return
    
    def _onFhResult (self, fh_result, fh_msg):
        if len(fh_msg.answer) == 0 or fh_msg.answer[0].rdtype != dns.rdatatype.FH:
            self.onError ("Query returned a data packet, but records in answer section (should not really happen)")
            return

        self.fh_result = fh_result
        self.fh_msg = fh_msg

        fh_rrdata = random.choice (fh_msg.answer[0].items)
        self.hint = fh_rrdata.hint

        self.zone = self.zone.append (self.label_real)
        self.label_real = ndn.Name ()
        self.label_logical = ndn.Name ()
        
        # next iteration or check for the result
        self._getMostSpecificNsAnswer (tryEmptyLabel = False)


    def _onVerifyFhData (self, fh_data, status):
        if not status:
            self.onError ('Got FH data but data is not trusted')
        else:
            self.onResult (self.fh_result, self.fh_msg)
        
    def _onNoMoreNsDelegation (self):
        if self.rrtype is None:
            ndns.TrustPolicy.verifyAsync (self.face, self.fh_result, self._onVerifyFhData)
            return
        
        if self.i < len(self.name):
            self.label_logical = self.label_logical.append (self.name[self.i:])

        _LOG.debug ('_onNoMoreNsDelegation [in %s for %s %s]' % (self.zone, self.label_logical, dns.rdatatype.to_text (self.rrtype)))

        # if len(label_real) == 0:
        #     if rrtype == dns.rdatatype.FH and not fh_msg is None and not fh_result is None:
        #         onResult (fh_result, fh_msg)
        #         return
        #     elif rrtype == dns.rdatatype.NS and not ns_msg is None and not ns_result is None:
        #         onResult (ns_result, ns_msg)
        #         return

        ndns.CachingQueryObj.expressQueryFor (self.face,
                                              self.onResult, self.onError,
                                              self.zone, self.hint, self.label_logical, self.rrtype, self.parse_dns)
    
