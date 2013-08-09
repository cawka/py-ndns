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

import ndns
import logging
import ndn
import time
import dns.rdatatype
from simple_query import SimpleQuery
from iterative_query import IterativeQuery

_LOG = logging.getLogger ("ndns.query.Caching")

class CachingQuery:
    def __init__ (self):
        self.cache = {}
        self.cache_zone = {}
        self.cache_raw = {}

    def expressQuery (self, 
                      face,
                      onResult, onError,
                      name, rrtype = dns.rdatatype.FH, parse_dns = True, verify = True):

        # _LOG.debug ('expressQuery')

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
                onResult (result, msg)
                return
                
        except KeyError:
            pass

        IterativeQuery.expressQuery (face, 
                                     ResultCacher (self.cache, key, onResult), onError, 
                                     name, rrtype, parse_dns, verify)

    def expressQueryForZoneFh (self, face, onResult, onError, zone, verify):
        key = str(zone)
        try:
            [result, msg, ttl] = self.cache_zone[key]
            if time.time () > ttl:
                del self.cache_zone[key]
            else:
                onResult (result, msg)
                return
        except KeyError:
            pass

        IterativeQuery.expressQueryForZoneFh (face, 
                                              ResultCacher (self.cache_zone, key, onResult), onError, zone, verify)
        
    def expressQueryForRaw (self,
                            face,
                            onResult, onError,
                            query, 
                            zone = None, hint = None, label = None, rrtype = None, parse_dns = True, limit_left = 10, verify = True):
        """
        Caching version of the most basic type of querying (:py:meth:`ndns.query.SimpleQuery.expressQueryForRaw`).  
        The user has to explicity specify the authority zone, forwarding hint, label, and resource record type.

        If ``zone``, ``label``, or ``rrtype`` are omitted or None, then they will be guessed from the query
        
        :param face: Face object
        :type face: ndn.Face
        :param onResult: Callback called when query returns a valid result:
        
            .. method:: onResult (data, dnsMessage)
            
                :param data: Data packet
                :type data: ndn.Data
                :param dnsMessage: if ``parse_dns`` flag is True, then fully parsed DNS message.
                                   if flag is False, then None
                :type dnsMessage: dns.Message
    
        :param onError: Callback called when query fails
    
            .. method:: onError (errorMessage)
    
                :param errorMessage: Error message with explanation of the error
                :type errorMessage: str
    
        :param query: NDN name of the query in form of ``<authority_zone>/DNS/<label(s)>/<RR-TYPE>``
        :type query: ndn.Name
        :param zone:
        :param hint:
        :param label:
        :param rrtype: RR type to query, e.g., "NS" or "FH" (default: infer from the query)
        :type rrtype: str
        :param parse_dns: Flag whether to parse DNS message or not (default True)
        :type parse_dns: bool
        """
        # _LOG.debug ('expressQueryForRaw')

        key = str (query)
        try:
            [result, msg, ttl] = self.cache_raw [key]
        
            if time.time () > ttl:
                del self.cache_raw[key]
            else:
                onResult (result, msg)
                return
        except KeyError:
            pass

        SimpleQuery.expressQueryForRaw (face, 
                                        ResultCacher (self.cache_raw, key, onResult), onError, 
                                        query, 
                                        zone, hint, label, rrtype, parse_dns, limit_left, verify)

    def expressQueryFor (self,
                         face,
                         onResult, onError,
                         zone, hint, label, rrtype, parse_dns = True, limit_left = 10, verify = True):

        # _LOG.debug ('expressQueryFor')
        if isinstance(rrtype, str):
            rrtype = dns.rdatatype.to_text (dns.rdatatype.from_text (rrtype))
        else:
            rrtype = dns.rdatatype.to_text (rrtype)
            
        query = ndn.Name (zone).append ("DNS")
        if len(label) > 0:
            query = query.append (label)
        query = query.append (rrtype)

        self.expressQueryForRaw (face, 
                                 onResult, onError, 
                                 query,
                                 zone, hint, label, rrtype, parse_dns, limit_left, verify)

class ResultCacher:
    def __init__ (self, cache, key, onResult):
        self.cache = cache
        self.key = key
        self.onResult = onResult

    def __call__ (self, ndn_data, dns_data):
        self.cache[self.key] = [ndn_data, dns_data, int (time.time ()) + ndn_data.signedInfo.freshnessSeconds]
        self.onResult (ndn_data, dns_data)
