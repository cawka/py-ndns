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
import logging, logging.handlers, sys, time
import ndns
import dns.rdatatype
import random

_LOG = logging.getLogger ("ndns.policy.Identity")

class IdentityPolicy:
    """
    Implementation of an identity policy
    """
    
    def __init__ (self, anchors = [], rules = [], chain_limit = 10):
        self.anchors = anchors
        self.rules = rules
        self.chain_limit = chain_limit

        self.trustedCacheLimit = 10000
        self.trustedCache = {}

    def verifyAsync (self, face, dataPacket, onVerify, limit_left = 10):
        """
        onVerify: callback <void, dataPacket, status>
        """

        if limit_left <= 0:
            onVerify (dataPacket, False)
            return

        if len (self.anchors) == 0:
            onVerify (dataPacket, False)
            return

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

            onVerify (dataPacket, True)
            return
        except KeyError:
            pass

        _LOG.debug ("%s data [%s] signed by [%s]" % ('--' * (11-limit_left), data_name, key_name))

        anchor = self.authorize_by_anchor (data_name, key_name)
        if anchor:
            verified = dataPacket.verify_signature (anchor)
            if verified:
                _LOG.info ("%s anchor OKs [%s] (**[%s]**)" % ('--' * (11-limit_left), data_name, key_name))
            else:
                _LOG.info ("%s anchor FAILs [%s]" % ('--' * (11-limit_left), data_name))
            onVerify (dataPacket, verified)
            return

        if not self.authorize_by_rule (data_name, key_name):
            onVerify (dataPacket, False)
            return

        try:
            [key, ttl] = self.trustedCache[str(key_name)]
            if time.time () > ttl:
                del self.trustedCache[str(key_name)]
                raise KeyError ()

            _LOG.info ("%s Using cached trusted version of key [%s]" % ('--' * (11-limit_left), key_name))

            onVerify (dataPacket, dataPacket.verify_signature (key))
            return
        except KeyError:
            zone = ndn.Name ()
            for comp in key_name:
                if comp == "DNS":
                    break
                zone = zone.append (comp)

            nextLevelProcessor = NextLevelProcessor (face, self, dataPacket, onVerify, limit_left)

            if comp != "DNS":
                face.expressInterest (key_name, nextLevelProcessor.onData, nextLevelProcessor.onTimeout)
            elif len (zone) == 0:
                ndns.CachingQueryObj.expressQueryForRaw (face, 
                                                         nextLevelProcessor.onKeyData, nextLevelProcessor.onError,
                                                         key_name,
                                                         hint = None, parse_dns = False, limit_left = limit_left-1)
            else:
                ndns.CachingQueryObj.expressQueryForRaw (face, 
                                                         nextLevelProcessor.onKeyData, nextLevelProcessor.onError,
                                                         key_name,
                                                         hint = None, parse_dns = False, limit_left = limit_left-1)
                # resolver = Resolver (face, nextLevelProcessor)
                # ndns.CachingQueryObj.expressQuery (face,
                #                                    resolver.onHintData, nextLevelProcessor.onError,
                #                                    zone, dns.rdatatype.FH, True)

    def authorize_by_anchor (self, data_name, key_name):
        # _LOG.debug ("== authorize_by_anchor == data: [%s], key: [%s]" % (data_name, key_name))

        for anchor in self.anchors:
            if key_name == anchor[0]:
                namespace_key = anchor[1]
                if namespace_key[:] == data_name[0:len (namespace_key)]:
                    return anchor[2]

        return None

    def authorize_by_rule (self, data_name, key_name):

        for rule in self.rules:
            matches_key = ndn.nre.match (rule[0], key_name)
            if matches_key:
                matches_data = ndn.nre.match (rule[2], data_name)

                if matches_data:
                    namespace_key  = matches_key.expand (rule[1])
                    namespace_data = matches_data.expand (rule[3])

                    if len (namespace_key) == 0 or namespace_key[:] == namespace_data[:len (namespace_key)]:
                        return True
        return False

# Helper classes

class NextLevelProcessor:
    def __init__ (self, face, policy, dataPacket, parentCallback, limit_left):
        self.face = face
        self.policy = policy
        self.dataPacket = dataPacket
        self.parentCallback = parentCallback
        self.limit_left = limit_left

    def onData (self, interest, keyDataPacket):
        key = ndn.Key.createFromDER (public = keyDataPacket.content)
        verified = self.dataPacket.verify_signature (key)

        if not verified:
            self.parentCallback (self.dataPacket, False)
            return

        _LOG.info ("%s policy OKs [%s] to be signed with [%s]" % ('--' * (11-self.limit_left), self.dataPacket.name, keyDataPacket.name))
        self.policy.verifyAsync (self.face, keyDataPacket, self, self.limit_left-1)

    def onTimeout (self, interest):
        self.parentCallback (self.dataPacket, False)

    def onError (self, error):
        self.parentCallback (self.dataPacket, False)


    def __call__ (self, keyDataPacket, status):
        # don't need to do anything with the keyDataPacket
        if not status:
            self.parentCallback (self.dataPacket, False)
            return

        if self.dataPacket.signedInfo.type == ndn.CONTENT_KEY:
            if len(self.policy.trustedCache) > self.policy.trustedCacheLimit:
                self.policy.trustedCache = {}

            self.policy.trustedCache[str(self.dataPacket.name)] = [ndn.Key.createFromDER (public = self.dataPacket.content),
                                                                   int (time.time ()) + self.dataPacket.signedInfo.freshnessSeconds]

        self.parentCallback (self.dataPacket, True)

    def onKeyData (self, keyDataPacket, not_used):
        self.onData (None, keyDataPacket)


# class Resolver:
#     def __init__ (self, face, processor):
#         self.face = face
#         self.processor = processor

#     def onHintData (self, fh_result, fh_msg):
#         hint = random.choice (fh_msg.answer[0].items).hint
#         ndns.CachingQueryObj.expressQueryForRaw (self.face,
#                                                  key_name, 
#                                                  self.onFhData, self.onError,
#                                                  hint = hint, parse_dns = False)

#     def onFhData (self, keyDataPacket, not_used):
#         self.processor.onData (None, keyDataPacket)

#     def onError (self, error):
#         self.processor.onError (error)
