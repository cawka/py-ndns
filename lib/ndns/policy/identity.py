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

import pyccn
import re, logging, logging.handlers, sys

class IdentityPolicy:
    def __init__ (self, anchors = [], rules = [], chain_limit = 10):
        self.anchors = anchors
        self.rules = rules
        self.chain_limit = chain_limit

        self._LOG = logging.getLogger ("ndns.policy.Identity")

    def verify (self, dataPacket, ndn = None):
        if len (self.anchors) == 0:
            return False

        if not ndn:
            _ndn = pyccn.CCN ()
            _ndn.defer_verification (True)

        limit_left = self.chain_limit
        
        while (limit_left > 0):
            data_name = dataPacket.name
            key_name = dataPacket.signedInfo.keyLocator.keyName

            self._LOG.debug ("data [%s] signed by [%s]" % (data_name, key_name))

            anchor = self.authorize_by_anchor (data_name, key_name)
            if anchor:
                verified = dataPacket.verify_signature (anchor)
                if verified:
                    self._LOG.info ("anchor OKs [%s] (**[%s]**)" % (data_name, key_name))
                else:
                    self._LOG.info ("anchor FAILs [%s]" % (data_name))
                return verified

            if not self.authorize_by_rule (data_name, key_name):
                return False

            keyDataPacket = _ndn.get (key_name, timeoutms = 3000)
            if not keyDataPacket:
                return False

            key = pyccn.Key.createFromDER (public = keyDataPacket.content)
            verified = dataPacket.verify_signature (key)
                
            if not verified:
                return False

            self._LOG.info ("policy OKs [%s] to be signed with [%s]" % (data_name, key_name))

            limit_left -= 1
            dataPacket = keyDataPacket
            # continue

        return False


    def authorize_by_anchor (self, data_name, key_name):
        # self._LOG.debug ("== authorize_by_anchor == data: [%s], key: [%s]" % (data_name, key_name))

        if not isinstance (data_name, pyccn.Name):
            data_name = pyccn.Name (data_name)

        if not isinstance (key_name, pyccn.Name):
            key_name = pyccn.Name (key_name)

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

                    namespace_key = pyccn.Name (namespace_key)
                    namespace_data = pyccn.Name (namespace_data)

                    self._LOG.debug ("  >> rule: key [%s], data [%s]" % (namespace_key, namespace_data))
                    
                    if namespace_key[:] == namespace_data[0:len (namespace_key)]:
                        return True
        return False
    
