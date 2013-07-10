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

import ndn
import re, logging, logging.handlers, sys, time
# import ndns.query
import ndns
import dns.rdatatype
import random

class IdentityPolicy:
    def __init__ (self, anchors = [], rules = [], chain_limit = 10):
        self.anchors = anchors
        self.rules = rules
        self.chain_limit = chain_limit

        self._LOG = logging.getLogger ("ndns.policy.Identity")

        self.trustedCacheLimit = 10000
        self.trustedCache = {}

    def verify (self, dataPacket, face = None, limit_left = 10):
        if limit_left <= 0:
            return false

        if len (self.anchors) == 0:
            return False

        if not face:
            face = ndn.Face ()
            face.defer_verification (True)

        data_name = dataPacket.name
        key_name = dataPacket.signedInfo.keyLocator.keyName

        try:
            [key_data, ttl] = self.trustedCache[str(data_name)]
            if time.time () > ttl:
                del self.trustedCache[str(data_name)]
                raise KeyError ()

            # self._LOG.info ("%s data [%s] (key) already verified" % ('--' * (11-limit_left), data_name))
            return True
        except KeyError:
            pass

        self._LOG.debug ("%s data [%s] signed by [%s]" % ('--' * (11-limit_left), data_name, key_name))

        anchor = self.authorize_by_anchor (data_name, key_name)
        if anchor:
            verified = dataPacket.verify_signature (anchor)
            if verified:
                self._LOG.info ("%s anchor OKs [%s] (**[%s]**)" % ('--' * (11-limit_left), data_name, key_name))
            else:
                self._LOG.info ("%s anchor FAILs [%s]" % ('--' * (11-limit_left), data_name))
            return verified

        if not self.authorize_by_rule (data_name, key_name):
            return False

        try:
            [key, ttl] = self.trustedCache[str(key_name)]
            if time.time () > ttl:
                del self.trustedCache[str(key_name)]
                raise KeyError ()

            self._LOG.info ("%s Using cached trusted version of key [%s]" % ('--' * (11-limit_left), key_name))
            return dataPacket.verify_signature (key)
        except KeyError:
            zone = ndn.Name ()
            for comp in key_name:
                if comp == "DNS":
                    break
                zone = zone.append (comp)

            if comp != "DNS":
                # self._LOG.info ("Key name does not belong to DNS, trying to fetch directly")
                keyDataPacket = face.get (key_name, timeoutms = 3000)
            elif len (zone) == 0:
                # self._LOG.info ("Key belongs to the root zone, no forwarding hint required")                
                [keyDataPacket, not_used] = ndns.CachingQueryObj.get_raw (key_name, hint = None, parse_dns = False)
            else:
                # self._LOG.info ("+++++ Key name belongs to DNS, trying to discover forwarding hint for it")
                try:
                    [fh_result, fh_msg] = ndns.CachingQueryObj.get (zone, dns.rdatatype.FH, True, face)
                    hint = random.choice (fh_msg.answer[0].items).hint
                    [keyDataPacket, not_used] = ndns.CachingQueryObj.get_raw (key_name, hint = hint, parse_dns = False)
                    
                except ndns.query.QueryException:
                    # self._LOG.info ("Cannot find what is the forwarding hint, trying to get directly")
                    keyDataPacket = face.get (key_name, timeoutms = 3000)

            if not keyDataPacket:
                return False
            
            key = ndn.Key.createFromDER (public = keyDataPacket.content)
            verified = dataPacket.verify_signature (key)
                
            if not verified:
                return False
            
            self._LOG.info ("%s policy OKs [%s] to be signed with [%s]" % ('--' * (11-limit_left), data_name, key_name))
            
            if not self.verify (keyDataPacket, face, limit_left-1):
                return False

            if dataPacket.signedInfo.type == ndn.CONTENT_KEY:
                if len(self.trustedCache) > self.trustedCacheLimit:
                    self.trustedCache = {}
                
                self.trustedCache[str(data_name)] = [ndn.Key.createFromDER (public = dataPacket.content), int (time.time ()) + dataPacket.signedInfo.freshnessSeconds]

            return True

    def authorize_by_anchor (self, data_name, key_name):
        # self._LOG.debug ("== authorize_by_anchor == data: [%s], key: [%s]" % (data_name, key_name))

        if not isinstance (data_name, ndn.Name):
            data_name = ndn.Name (data_name)

        if not isinstance (key_name, ndn.Name):
            key_name = ndn.Name (key_name)

        for anchor in self.anchors:
            if key_name == anchor[0]:
                namespace_key = anchor[1]
                if namespace_key[:] == data_name[0:len (namespace_key)]:
                    return anchor[2]
                
        return None

    def authorize_by_rule (self, data_name, key_name):
        # self._LOG.debug ("== authorize_by_rule == data: [%s], key: [%s]" % (data_name, key_name))

        if not isinstance (data_name, str):
            data_name = str (data_name)

        if not isinstance (key_name, str):
            key_name = str (key_name)

        for rule in self.rules:
            matches_key = re.match (rule[0], key_name)
            if matches_key:
                matches_data = re.match (rule[2], data_name)

                if matches_data:
                    namespace_key  = matches_key.expand (rule[1])
                    namespace_data = matches_data.expand (rule[3])
                    if len(namespace_key) == 0:
                        namespace_key = "/"

                    if len(namespace_data) == 0:
                        namespace_data = "/"

                    namespace_key = ndn.Name (namespace_key)
                    namespace_data = ndn.Name (namespace_data)

                    # self._LOG.debug ("  >> rule: key [%s], data [%s]" % (namespace_key, namespace_data))
                    
                    if namespace_key[:] == namespace_data[0:len (namespace_key)]:
                        return True
        return False
    
