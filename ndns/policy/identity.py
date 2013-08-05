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


class IdentityPolicy:
    """
    Implementation of an identity policy
    """
    
    def __init__ (self, anchors = [], rules = [], chain_limit = 10):
        self.anchors = anchors
        self.rules = rules
        self.chain_limit = chain_limit

        self._LOG = logging.getLogger ("ndns.policy.Identity")

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

        self._LOG.debug ("%s data [%s] signed by [%s]" % ('--' * (11-limit_left), data_name, key_name))

        anchor = self.authorize_by_anchor (data_name, key_name)
        if anchor:
            verified = dataPacket.verify_signature (anchor)
            if verified:
                self._LOG.info ("%s anchor OKs [%s] (**[%s]**)" % ('--' * (11-limit_left), data_name, key_name))
            else:
                self._LOG.info ("%s anchor FAILs [%s]" % ('--' * (11-limit_left), data_name))
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

            self._LOG.info ("%s Using cached trusted version of key [%s]" % ('--' * (11-limit_left), key_name))

            onVerify (dataPacket, dataPacket.verify_signature (key))
            return
        except KeyError:
            zone = ndn.Name ()
            for comp in key_name:
                if comp == "DNS":
                    break
                zone = zone.append (comp)

            nextLevelProcessor = NextLevelProcessor (self, face, dataPacket, onVerify)

            if comp != "DNS":
                face.expressInterest (key_name, nextLevelProcessor.onData, nextLevelProcessor.onTimeout)
            elif len (zone) == 0:
                keyResolver = KeyResolver (nextLevelProcessor)
                ndns.CachingQueryObj.expressQueryForRaw (key_name, face, 
                                                         keyResolver.onKeyData, nextLevelProcessor.onError, nextLevelProcessor.onTimeout,
                                                         hint = None, parse_dns = False)
            else:
                try:
                    resolver = Resolver (face, nextLevelProcessor)
                    ndns.CachingQueryObj.expressQueryFor (face, zone, dns.rdatatype.FH, True,
                                                          resolver.onHintData, nextLevelProcessor.onError, nextLevelProcessor.onTimeout)

                except ndns.query.QueryException:
                    face.expressInterest (key_name, nextLevelProcessor.onData, nextLevelProcessor.onTimeout)

    def authorize_by_anchor (self, data_name, key_name):
        # self._LOG.debug ("== authorize_by_anchor == data: [%s], key: [%s]" % (data_name, key_name))

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

                    if namespace_key[:] == namespace_data[0:len (namespace_key)]:
                        return True
        return False

# Helper classes

class RecursiveVerifier:
    def __init__ (self, parentCallback):
        self.parentCallback = parentCallback

    def __call__ (self, dataPacket, status):
        if not status:
            self.parentCallback (dataPacket, False)
            return

        if dataPacket.signedInfo.type == ndn.CONTENT_KEY:
            if len(self.trustedCache) > self.trustedCacheLimit:
                self.trustedCache = {}

            self.trustedCache[str(data_name)] = [ndn.Key.createFromDER (public = dataPacket.content),
                                                 int (time.time ()) + dataPacket.signedInfo.freshnessSeconds]

        self.parentCallback (dataPacket, True)

class NextLevelProcessor:
    def __init__ (self, face, policy, dataPacket, parentCallback):
        self.face = face
        self.policy = policy
        self.dataPacket = dataPacket
        self.parentCallback = parentCallback

    def onData (self, interest, keyDataPacket):
        key = ndn.Key.createFromDER (public = keyDataPacket.content)
        verified = dataPacket.verify_signature (key)

        if not verified:
            self.parentCallback (dataPacket, False)
            return

        self.policy._LOG.info ("%s policy OKs [%s] to be signed with [%s]" % ('--' * (11-limit_left), data_name, key_name))
        self.policy.verifyAsync (keyDataPacket, self.face, RecursiveVerifier (self.parentCallback), limit_left-1)

    def onTimeout (self, interest):
        self.parentCallback (self.dataPacket, False)

    def onError (self, error):
        self.parentCallback (self.dataPacket, False)

class KeyResolver:
    def __init__ (self, processor):
        self.processor = processor

    def onKeyData (self, keyDataPacket, not_used):
        self.processor.onData (None, keyDataPacket)

class Resolver:
    def __init__ (self, face, processor):
        self.face = face
        self.processor = processor

    def onHintData (self, fh_result, fh_msg):
        hint = random.choice (fh_msg.answer[0].items).hint
        ndns.CachingQueryObj.expressQueryForRaw (key_name, self.face,
                                                 self.onFhData, self.onError, self.processor.onTimeout,
                                                 hint = hint, parse_dns = False)

    def onFhData (self, keyDataPacket, not_used):
        self.processor.onData (None, keyDataPacket)

    def onError (self, error):
        self.processor.onError (error)
