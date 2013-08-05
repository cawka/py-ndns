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

# from dnsifier import *

# import dns.rdataclass
# import dns.rdatatype
# import dns.rdata
# import dns.rrset
# import dns.message
# import dns.rdtypes.IN.NDNCERT
# import ndns
# import re
# import random
import logging
# import ndn
# import time

_LOG = logging.getLogger ("ndns.query.Iterative")

class IterativeQuery:
    pass

#     @staticmethod
#     def _mergeIter (i1, i2):
#         for i in i1:
#             yield i
#         for i in i2:
#             yield i

#     @staticmethod
#     def _getMostSpecificAnswer (zone, hint, name_iter, rtype, tryEmptyLabel, face):
#         result = None
#         msg = None
#         label_real = ndn.Name ()
#         label_logical = ndn.Name ()
        
#         try:
#             if tryEmptyLabel:
#                 label_logical = ndn.Name ()
#                 label_real = ndn.Name ()
#             else:
#                 component = name_iter.next ()

#                 label_logical = ndn.Name ().append (ndnify (component))
#                 label_real = ndn.Name ().append (component)

#             [result, msg] = ndns.CachingQueryObj.get_simple (zone, hint, label_logical, rtype, True, face)
#             while (len(msg.answer)==0 and len(msg.authority)==1 and msg.authority[0].rdtype == dns.rdatatype.NDNAUTH):
#                 component = name_iter.next ()

#                 label_logical = label_logical.append (ndnify (component))
#                 label_real = label_real.append (component)

#                 [result, msg] = ndns.CachingQueryObj.get_simple (zone, hint, label_logical, rtype, True, face)
           
#             if len(msg.answer) == 0 or msg.answer[0].rdtype != rtype:
#                 raise QueryNoValidAnswer (msg, result, label_real)

#         except StopIteration:
#             pass

#         if result is None or msg is None or label_logical is None or label_real is None:
#             raise QueryNoValidAnswer (msg, result, label_real)
#         else:
#             return [result, msg, label_logical, label_real]


#     @staticmethod
#     def get (name, rrtype = dns.rdatatype.FH, parse_dns = True, face = None):
#         if rrtype is None:
#             rrtype = dns.rdatatype.FH

#         if isinstance (rrtype, str):
#             rrtype = dns.rdatatype.from_text (rrtype)

#         _LOG.debug ("IterativeQuery: name: %s, type: %s" % (name, dns.rdatatype.to_text (rrtype)))

#         zone = ndn.Name ()
#         hint = None
#         [fh_result, fh_msg] = [None, None]

#         if not face:
#             face = ndn.Face ()
#             face.defer_verification ()
        
#         try:
#             label_real = ndn.Name ()
#             name_iter = iter(name)
#             while True:
#                 # _LOG.debug ("IterativeQuery: hint: %s, zone: %s" % (hint, zone))

#                 [ns_result, ns_msg, label_logical, label_real] = \
#                     IterativeQuery._getMostSpecificAnswer (zone, hint, name_iter, 
#                                                            dns.rdatatype.NS, tryEmptyLabel = False, face = face)

#                 ns_rrdata = random.choice (ns_msg.answer[0].items)

#                 # A couple of cheats, to handle names like "/ndn/ucla.edu/irl"

#                 # ns_target = ndnify (ns_rrdata.target.relativize (dns.name.root).to_text ())
#                 dns_zone = dns.name.from_text (dnsify (str(zone)))
#                 dns_ns_target = ns_rrdata.target
                
#                 if dns_ns_target.is_subdomain (dns_zone):
#                     ns_label = ndn.Name (ndnify (dns_ns_target.relativize (dns_zone).to_text ()))
#                     [fh_result, fh_msg] = ndns.CachingQueryObj.get_simple (zone, hint, ns_label, dns.rdatatype.FH, True, face)
#                 else:
#                     ns_target = ndn.Name (ndnify (dns_ns_target.relativize (dns.name.root).to_text ()))
#                     [fh_result, fh_msg] = IterativeQuery.get (ns_target, dns.rdatatype.FH, True, face)
                
#                 # if zone.isPrefixOf (ns_target):
#                 #     fh_label = ndn.Name (ns_target[len(zone):])
#                 #     [fh_result, fh_msg] = ndns.CachingQueryObj.get_simple (zone, hint, fh_label, dns.rdatatype.FH, True, face)
#                 # else:
#                 #     [fh_result, fh_msg] = IterativeQuery.get (ns_target, dns.rdatatype.FH, True, face)
                    
#                 if len(fh_msg.answer) == 0 or fh_msg.answer[0].rdtype != dns.rdatatype.FH:
#                     raise QueryNoAnswer ()

#                 fh_rrdata = random.choice (fh_msg.answer[0].items)
#                 hint = fh_rrdata.hint

#                 zone = zone.append (label_real)
#                 label_real = ndn.Name ()

#         except QueryNoValidAnswer, e:
#             label_real = e.label_real
#         except StopIteration:
#             pass
        
#         for comp in name_iter:
#             label_real = label_real.append (comp)

#         if len(label_real) == 0:
#             if rrtype == dns.rdatatype.FH and not fh_msg is None and not fh_result is None:
#                 return [fh_result, fh_msg]
#             elif rrtype == dns.rdatatype.NS and not ns_msg is None and not ns_result is None:
#                 return [ns_result, ns_msg]

#         [real_result, real_msg] = ndns.CachingQueryObj.get_simple (zone, hint, label_real, rrtype, parse_dns, face)
#         return [real_result, real_msg]

