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

import pyccn

class QueryException (Exception):
    pass

class QueryNoAnswer (QueryException):
    pass

class QueryAnswerNotTrusted (QueryException):
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

        result = ndn.get (query)
    
        if not result:
            raise QueryNoAnswer
        
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

        rrtype = dns.rdatatype.to_text (dns.rdatatype.from_text (rrtype))

        query = pyccn.Name (zone).append ("DNS")
        if len(label) > 0:
            for comp in label[0:len(label)]:
                query = query.append (comp)
        query = query.append (rrtype)

        return SimpleQuery.get_raw (query, zone, hint, label, rrtype, parse_dns, ndn)
        

class IterativeQuery:
    pass

class CachingQuery:
    pass
