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
import time

_LOG = logging.getLogger ("ndns.query")

class QueryException (Exception):
    pass

class QueryNoAnswer (QueryException):
    pass

class QueryAnswerNotTrusted (QueryException):
    def __init__ (self, result = None):
        self.result = result

class QueryNoValidAnswer (QueryException):
    def __init__ (self, msg = None, result = None, label_real = None):
        self.msg = msg
        self.result = result
        self.label_real = label_real

class SimpleQuery:
    """This is the most basic type of querying.  The user has to explicity 
    specify the authority zone, forwarding hint, label, and resource record type"""

    @staticmethod
    def get_raw (query, zone = None, hint = None, label = None, rrtype = None, parse_dns = True, ndn = None):
        """If zone, label, or rrtype is None, then they will be guessed from the query"""

        _LOG.debug ("SimpleQuery.get_raw: query: %s, hint: %s" % (query, hint))

        if not ndn:
            ndn = pyccn.CCN ()
            ndn.defer_verification ()

        if hint and not hint.isPrefixOf (query):
            query = pyccn.Name (hint).append ("\xF0.").append (query)
        else:
            hint = None

        result = ndn.get (query)
    
        if not result:
            raise QueryNoAnswer

        if hint:
            # don't verify the outer part, it cannot be verified for now anyways
            result = pyccn.ContentObject.from_ccnb (result.content)

        if not ndns.TrustPolicy.verify (result):
            raise QueryAnswerNotTrusted (result)
            
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

class IterativeQuery:
    @staticmethod
    def _mergeIter (i1, i2):
        for i in i1:
            yield i
        for i in i2:
            yield i

    @staticmethod
    def _getMostSpecificAnswer (zone, hint, name_iter, rtype, tryEmptyLabel, ndn):
        result = None
        msg = None
        label_real = pyccn.Name ()
        label_logical = pyccn.Name ()
        
        try:
            if tryEmptyLabel:
                label_logical = pyccn.Name ()
                label_real = pyccn.Name ()
            else:
                component = name_iter.next ()

                label_logical = pyccn.Name ().append (ndnify (component))
                label_real = pyccn.Name ().append (component)

            [result, msg] = ndns.CachingQueryObj.get_simple (zone, hint, label_logical, rtype, True, ndn)
            while (len(msg.answer)==0 and len(msg.authority)==1 and msg.authority[0].rdtype == dns.rdatatype.NDNAUTH):
                component = name_iter.next ()

                label_logical = label_logical.append (ndnify (component))
                label_real = label_real.append (component)

                [result, msg] = ndns.CachingQueryObj.get_simple (zone, hint, label_logical, rtype, True, ndn)
           
            if len(msg.answer) == 0 or msg.answer[0].rdtype != rtype:
                raise QueryNoValidAnswer (msg, result, label_real)

        except StopIteration:
            pass

        if result is None or msg is None or label_logical is None or label_real is None:
            raise QueryNoValidAnswer (msg, result, label_real)
        else:
            return [result, msg, label_logical, label_real]


    @staticmethod
    def get (name, rrtype = dns.rdatatype.FH, parse_dns = True, ndn = None):
        if rrtype is None:
            rrtype = dns.rdatatype.FH

        if isinstance (rrtype, str):
            rrtype = dns.rdatatype.from_text (rrtype)

        _LOG.debug ("IterativeQuery: name: %s, type: %s" % (name, dns.rdatatype.to_text (rrtype)))

        zone = pyccn.Name ()
        hint = None

        if not ndn:
            ndn = pyccn.CCN ()
            ndn.defer_verification ()
        
        try:
            label_real = pyccn.Name ()
            name_iter = iter(name)
            while True:
                # _LOG.debug ("IterativeQuery: hint: %s, zone: %s" % (hint, zone))

                [ns_result, ns_msg, label_logical, label_real] = \
                    IterativeQuery._getMostSpecificAnswer (zone, hint, name_iter, 
                                                           dns.rdatatype.NS, tryEmptyLabel = False, ndn = ndn)

                ns_rrdata = random.choice (ns_msg.answer[0].items)

                # A couple of cheats, to handle names like "/ndn/ucla.edu/irl"

                # ns_target = ndnify (ns_rrdata.target.relativize (dns.name.root).to_text ())
                dns_zone = dns.name.from_text (dnsify (str(zone)))
                dns_ns_target = ns_rrdata.target
                
                if dns_ns_target.is_subdomain (dns_zone):
                    ns_label = pyccn.Name (ndnify (dns_ns_target.relativize (dns_zone).to_text ()))
                    [fh_result, fh_msg] = ndns.CachingQueryObj.get_simple (zone, hint, ns_label, dns.rdatatype.FH, True, ndn)
                else:
                    ns_target = pyccn.Name (ndnify (dns_ns_target.relativize (dns.name.root).to_text ()))
                    [fh_result, fh_msg] = IterativeQuery.get (ns_target, dns.rdatatype.FH, True, ndn)
                
                # if zone.isPrefixOf (ns_target):
                #     fh_label = pyccn.Name (ns_target[len(zone):])
                #     [fh_result, fh_msg] = ndns.CachingQueryObj.get_simple (zone, hint, fh_label, dns.rdatatype.FH, True, ndn)
                # else:
                #     [fh_result, fh_msg] = IterativeQuery.get (ns_target, dns.rdatatype.FH, True, ndn)
                    
                if len(fh_msg.answer) == 0 or fh_msg.answer[0].rdtype != dns.rdatatype.FH:
                    raise QueryNoAnswer ()

                fh_rrdata = random.choice (fh_msg.answer[0].items)
                hint = fh_rrdata.hint

                zone = zone.append (label_real)
                label_real = pyccn.Name ()

        except QueryNoValidAnswer, e:
            label_real = e.label_real
        except StopIteration:
            pass
        
        for comp in name_iter:
            label_real = label_real.append (comp)

        if len(label_real) == 0:
            if rrtype == dns.rdatatype.FH and not fh_msg is None and not fh_result is None:
                return [fh_result, fh_msg]
            elif rrtype == dns.rdatatype.NS and not ns_msg is None and not ns_result is None:
                return [ns_result, ns_msg]

        [real_result, real_msg] = ndns.CachingQueryObj.get_simple (zone, hint, label_real, rrtype, parse_dns, ndn)
        return [real_result, real_msg]

class CachingQuery:
    def __init__ (self):
        self.cache = {}
        self.cache_raw = {}

    def get (self, name, rrtype = dns.rdatatype.FH, parse_dns = True, ndn = None):
        if rrtype is None:
            rrtype = dns.rdatatype.FH

        if isinstance (rrtype, str):
            rrtype = dns.rdatatype.from_text (rrtype)

        class Key:
            def __init__ (self, name, type):
                self.name = name
                self.type = type
    
            def __eq__ (self, other):
                return self.name == other.name and self.type == other.type
    
            def __ne__ (self, other):
                return self.name != other.name or self.type != other.type
    
            def __hash__ (self):
                return str(self.name).__hash__ () + self.type

        key = Key (name, rrtype)
        try:
            [result, msg, ttl] = self.cache[key]
            if time.time () > ttl:
                del self.cache[key]
            else:
                # _LOG.debug ("              found in cache")
                return [result, msg]

        except KeyError:
            pass

        # _LOG.debug ("CachingQuery: name: %s, type: %s" % (name, dns.rdatatype.to_text (rrtype)))
        
        [result, msg] = IterativeQuery.get (name, rrtype, parse_dns)
        self.cache[key] = [result, msg, int (time.time ()) + result.signedInfo.freshnessSeconds]

        return [result, msg]

    def get_raw (self, query, zone = None, hint = None, label = None, rrtype = None, parse_dns = True, ndn = None):
        key = str (query)
        try:
            [result, msg, ttl] = self.cache_raw [key]
        
            if time.time () > ttl:
                del self.cache_raw[key]
            else:
                # _LOG.debug ("                   found in cache_raw [%s]" % (query))
                return [result, msg]

        except KeyError:
            pass

        # _LOG.debug ("CachingQuery.raw: [%s]" % (query))
        [result, msg] = SimpleQuery.get_raw (query, zone, hint, label, rrtype, parse_dns, ndn)
        self.cache_raw[key] = [result, msg, int (time.time ()) + result.signedInfo.freshnessSeconds]

        return [result, msg]

    def get_simple (self, zone, hint, label, rrtype, parse_dns = True, ndn = None):
        if isinstance(rrtype, str):
            rrtype = dns.rdatatype.to_text (dns.rdatatype.from_text (rrtype))
        else:
            rrtype = dns.rdatatype.to_text (rrtype)

        query = pyccn.Name (zone).append ("DNS")
        if len(label) > 0:
            query = query.append (label)
        query = query.append (rrtype)

        return self.get_raw (query, zone, hint, label, rrtype, parse_dns, ndn)
