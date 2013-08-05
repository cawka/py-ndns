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

_LOG = logging.getLogger ("ndns.query.Caching")

class CachingQuery:
    def __init__ (self):
        self.cache = {}
        self.cache_raw = {}

    # def get (self, name, rrtype = dns.rdatatype.FH, parse_dns = True, face = None):
    #     if rrtype is None:
    #         rrtype = dns.rdatatype.FH

    #     if isinstance (rrtype, str):
    #         rrtype = dns.rdatatype.from_text (rrtype)

    #     class Key:
    #         def __init__ (self, name, type):
    #             self.name = name
    #             self.type = type
    
    #         def __eq__ (self, other):
    #             return self.name == other.name and self.type == other.type
    
    #         def __ne__ (self, other):
    #             return self.name != other.name or self.type != other.type
    
    #         def __hash__ (self):
    #             return str(self.name).__hash__ () + self.type

    #     key = Key (name, rrtype)
    #     try:
    #         [result, msg, ttl] = self.cache[key]
    #         if time.time () > ttl:
    #             del self.cache[key]
    #         else:
    #             # _LOG.debug ("              found in cache")
    #             return [result, msg]

    #     except KeyError:
    #         pass

    #     # _LOG.debug ("CachingQuery: name: %s, type: %s" % (name, dns.rdatatype.to_text (rrtype)))
        
    #     [result, msg] = IterativeQuery.get (name, rrtype, parse_dns)
    #     self.cache[key] = [result, msg, int (time.time ()) + result.signedInfo.freshnessSeconds]

    #     return [result, msg]

    def expressQueryForRaw (self,
                            face,
                            query, 
                            onResult, onError,
                            zone = None, hint = None, label = None, rrtype = None, parse_dns = True):
        key = str (query)
        try:
            [result, msg, ttl] = self.cache_raw [key]
        
            if time.time () > ttl:
                del self.cache_raw[key]
            else:
                return [result, msg]
        except KeyError:
            pass

        class ResultCacher:
            def __init__ (self, cache, onResult):
                self.cache = cache
                self.onResult = onResult

            def __call__ (self, onData):
                pass
        
        [result, msg] = SimpleQuery.expressQueryForRaw (face, query, onResult, onError, zone, hint, label, rrtype, parse_dns)


        self.cache_raw[key] = [result, msg, int (time.time ()) + result.signedInfo.freshnessSeconds]

        return [result, msg]

    def get_simple (self, zone, hint, label, rrtype, parse_dns = True, face = None):
        if isinstance(rrtype, str):
            rrtype = dns.rdatatype.to_text (dns.rdatatype.from_text (rrtype))
        else:
            rrtype = dns.rdatatype.to_text (rrtype)

        query = ndn.Name (zone).append ("DNS")
        if len(label) > 0:
            query = query.append (label)
        query = query.append (rrtype)

        return self.get_raw (query, zone, hint, label, rrtype, parse_dns, face)
