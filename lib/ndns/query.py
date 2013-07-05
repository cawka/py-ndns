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

from dnsifier import *

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
import pyccn

_LOG = logging.getLogger ("ndns.query")

class QueryException (Exception):
    pass

class QueryNoAnswer (QueryException):
    pass

class QueryAnswerNotTrusted (QueryException):
    pass

class QueryNoValidAnswer (QueryException):
    pass

class SimpleQuery:
    """This is the most basic type of querying.  The user has to explicity 
    specify the authority zone, forwarding hint, label, and resource record type"""

    @staticmethod
    def get_raw (query, zone = None, hint = None, label = None, rrtype = None, parse_dns = True, ndn = None):
        """If zone, label, or rrtype is None, then they will be guessed from the query"""

        if not ndn:
            ndn = pyccn.CCN ()
            ndn.defer_verification ()

        if hint:
            query = pyccn.Name (hint).append ("\xF0.").append (query)

        result = ndn.get (query)
    
        if not result:
            raise QueryNoAnswer

        if hint:
            # don't verify the outer part, it cannot be verified for now anyways
            result = pyccn.ContentObject.from_ccnb (result.content)

        if not ndns.TrustPolicy.verify (result):
            raise QueryAnswerNotTrusted
            
        if parse_dns:
            try:
                msg = dns.message.from_wire (result.content)
            except:
                if not rrtype:
                    rrtype = query[-1] if query[-1][0] != '\xFD' else query[-2]
    
                if rrtype == "NDNCERT":
                    if not zone or not label:
                        matches = re.match ("^((/[^/]+)*)/DNS((/[^/]+)*)/NDNCERT", str(query))
                        if not matches:
                            raise QueryException ("Incorrectly formatted query [%s]" % query)
    
                        dns_zone = dns.name.from_text (dnsify(str(matches.group (1))))
                        dns_label = dns.name.from_text (dnsify(str(matches.group (3))), origin = dns_zone)
                    else:
                        dns_zone = dns.name.from_text (dnsify(str(zone)))
                        dns_label = dns.name.from_text (dnsify(str(label)), origin = dns_zone)
    
                    ndncert = dns.rdtypes.IN.NDNCERT.NDNCERT (dns.rdataclass.IN, dns.rdatatype.NDNCERT, result.content)
                    rrset = dns.rrset.RRset (dns_label, dns.rdataclass.IN, dns.rdatatype.NDNCERT)
                    rrset.add (ttl = result.signedInfo.freshnessSeconds, rd = ndncert)
        
                    msg = dns.message.Message (id=0)
                    msg.answer.append (rrset)
                else:
                    msg = dns.message.from_wire (result.content)
        else:
            msg = None

        return [result, msg]

    @staticmethod
    def get (zone, hint, label, rrtype, parse_dns = True, ndn = None):
        """hint is not used for now"""

        _LOG.debug ("SimpleQuery: zone: %s, hint: %s, label %s, rrtype: %s" % (zone, hint, label, rrtype))
        rrtype = dns.rdatatype.to_text (dns.rdatatype.from_text (rrtype))

        query = pyccn.Name (zone).append ("DNS")
        if len(label) > 0:
            query = query.append (label)
        query = query.append (rrtype)

        return SimpleQuery.get_raw (query, zone, hint, label, rrtype, parse_dns, ndn)

class IterativeQuery:
    @staticmethod
    def get (name, rrtype = "FH", ndn = None):
        _LOG.debug ("IterativeQuery: name: %s, type: %s" % (name, rrtype))
        zone = pyccn.Name ()
        hint = None

        if not ndn:
            ndn = pyccn.CCN ()
            ndn.defer_verification ()
        
        i = 0
        while i < len(name):
            label = pyccn.Name ().append (name[i])

            [result, msg] = SimpleQuery.get (zone, hint, label, "NS", True, ndn)
            while (i+1) < len(name) and (len(msg.answer)==0 and len(msg.authority)==1 and msg.authority[0].rdtype == dns.rdatatype.NDNAUTH):
                i += 1
                label = label.append (name[i])
                [result, msg] = SimpleQuery.get (zone, hint, label, "NS", True, ndn)
               
            if len(msg.answer) == 0 or msg.answer[0].rdtype != dns.rdatatype.NS:
                break
                # raise QueryNoValidAnswer ()

            rrdata = random.choice (msg.answer[0].items)
            ndn_target = ndnify (rrdata.target.relativize (dns.name.root).to_text ())

            if zone.isPrefixOf (ndn_target):
                fh_label = pyccn.Name (ndn_target[len(zone):])
                [result, msg] = SimpleQuery.get (zone, hint, fh_label, "FH", True, ndn)
            else:
                msg = IterativeQuery.get (ndn_target, ndn)

            zone = zone.append (label)
            label = pyccn.Name ()

            if len(msg.answer) == 0 or msg.answer[0].rdtype != dns.rdatatype.FH:
                break

            rrdata = random.choice (msg.answer[0].items)
            hint = rrdata.hint

            _LOG.debug ("IterativeQuery: hint: %s, zone: %s" % (hint, zone))
            i += 1

        [result, msg] = SimpleQuery.get (zone, hint, label, rrtype, True, ndn)
        while (i+1) < len(name) and (len(msg.answer)==0 and len(msg.authority)==1 and msg.authority[0].rdtype == dns.rdatatype.NDNAUTH):
            i += 1
            label = label.append (name[i])
            [result, msg] = SimpleQuery.get (zone, hint, label, rrtype, True, ndn)

        return [result, msg]

class CachingQuery:
    pass
