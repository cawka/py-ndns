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

from ndns.dnsifier import *

import dns.rdataclass
import dns.rdatatype
import dns.rdata
import dns.rrset
import dns.message
import dns.rdtypes.IN.NDNCERT
import ndns
import random
import logging
import ndn
import time

_LOG = logging.getLogger ("ndns.query.Simple")

class SimpleQuery:
    def __init__ (self, face,
                  onResult, onError,
                  query,
                  zone = None, hint = None, label = None, rrtype = None, parse_dns = True, limit_left = 10):
        self.face = face
        self.query = query
        self.onResult = onResult
        self.onError = onError
        self.zone = zone
        self.hint = hint
        self.label = label
        self.rrtype = rrtype
        self.parse_dns = parse_dns
        self.limit_left = limit_left

    def _onVerify (self, dataPacket, status):
        if not status:
            return self.onError ("Query answer not trusted")

        if self.parse_dns:
            try:
                msg = dns.message.from_wire (dataPacket.content)
            except:
                if not self.rrtype:
                    self.rrtype = self.query[-1] if self.query[-1][0] != '\xFD' else self.query[-2]

                if self.rrtype == "NDNCERT":
                    if not self.zone or not self.label:
                        matches = ndn.nre.match ("(<>*)<DNS>(<>*)<NDNCERT>", self.query)
                        if not matches:
                            return self.onError ("Incorrectly formatted query [%s]" % self.query)

                        dns_zone = dns.name.from_text (dnsify (str (matches.expand ("\\1"))))
                        dns_label = dns.name.from_text (dnsify (str (matches.expand ("\\2"))), origin = dns_zone)
                    else:
                        dns_zone = dns.name.from_text (dnsify (str (self.zone)))
                        dns_label = dns.name.from_text (dnsify (str (self.label)), origin = dns_zone)

                    ndncert = dns.rdtypes.IN.NDNCERT.NDNCERT (dns.rdataclass.IN, dns.rdatatype.NDNCERT, dataPacket.content)
                    rrset = dns.rrset.RRset (dns_label, dns.rdataclass.IN, dns.rdatatype.NDNCERT)
                    rrset.add (ttl = dataPacket.signedInfo.freshnessSeconds, rd = ndncert)

                    msg = dns.message.Message (id=0)
                    msg.answer.append (rrset)
                else:
                    msg = dns.message.from_wire (dataPacket.content)
        else:
            msg = None

        return self.onResult (dataPacket, msg)

    def _onData (self, interest, data):
        if self.hint:
            # don't verify the outer part, it cannot be verified for now anyways
            data = ndn.Data.fromWire (data.content)

        ndns.TrustPolicy.verifyAsync (self.face, data, self._onVerify, self.limit_left)

    def _onTimeout (self, interest):
        return self.onError ("Query timed out")

    @staticmethod
    def expressQueryForRaw (face,
                            onResult, onError,
                            query,
                            zone = None, hint = None, label = None, rrtype = None, parse_dns = True, limit_left = 10):
        """
        This is the most basic type of querying.  The user has to explicity
        specify the authority zone, forwarding hint, label, and resource record type1

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

        _LOG.debug ("SimpleQuery.expressQueryForRaw: query: %s, hint: %s" % (query, hint))

        if hint and not hint.isPrefixOf (query):
            query = ndn.Name (hint).append ("\xF0.").append (query)
        else:
            hint = None

        state = SimpleQuery (face,
                             onResult, onError,
                             query,
                             zone, hint, label, rrtype, parse_dns, limit_left)
        face.expressInterest (query, state._onData, state._onTimeout)
