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

import logging
import ndn
import dns.rdataclass, dns.rdatatype, dns.rdata, dns.rrset, dns.zone
import os, functools

# part of lib/
import ndns
import dns.rdtypes.IN.NDNAUTH
import dns.rdtypes.IN.NEXISTS
import dns.rdtypes.IN.NDNCERTSEQ

_LOG = logging.getLogger ("ndns.DaemonSim")

class NdnsDaemonSim (object):
#public:
    def __init__ (self, data_dir, scopes = [], enable_dyndns = True):
        self.data_dir = data_dir
        self._scopes = [ndn.Name (scope) for scope in scopes]

        self._zones = []
        self._autoScope = []
        self._enable_dyndns = enable_dyndns

    def run (self):
        _LOG.info ('Daemon started')

        self._ndns = ndns.ndns_session (self.data_dir)
        self._face = ndn.Face ()

        self._startZoneServing ()

        self._eventLoop = ndn.EventLoop (self._face)
        self._eventLoop.run ()

        _LOG.info ('Daemon stopped')

    def terminate (self):
        self._stopZoneServing ()
        self._eventLoop.stop ()
        self._face = None
        self._ndns = None

#private:
    def _enableZone (self, zone):
        name = zone.name

        self._face.setInterestFilter (ndn.Name (name).append ("DNS"),
                                      functools.partial (self._onRequest, ndn.Name (), zone))

        activeScopes = []
        for scope in self._scopes + self._autoScope:
            if not scope.isPrefixOf (name):
                activeScopes.append (str (scope))
                self._face.setInterestFilter (ndn.Name (scope).append ("\xF0.").append (name).append ("DNS"),
                                              functools.partial (self._onRequest, ndn.Name (scope).append ("\xF0."), zone))
        _LOG.info ('>> Start serving zone [%s] (%s)' % (name, activeScopes))

    def _disableZone (self, zone):
        name = zone.name

        self._face.clearInterestFilter (ndn.Name (name).append ("DNS"))

        activeScopes = []
        for scope in self._scopes + self._autoScope:
            if not scope.isPrefixOf (name):
                activeScopes.append (str (scope))
                self._face.clearInterestFilter (ndn.Name (scope).append ("\xF0.").append (name).append ("DNS"))

        _LOG.info ('<< Stop serving zone [%s] (%s)' % (name, activeScopes))

    def _startZoneServing (self):
        for zone in self._ndns.query (ndns.Zone):
            self._enableZone (zone)
            self._zones.append (zone)

    def _stopZoneServing (self):
        for zone in self._zones:
            self._disableZone (zone)
        self._zones = []

    def _onRequest (self, scope, zone, basename, interest):
        _LOG.debug (">> scope [%s], zone [%s], basename [%s], interest [%s]" % (scope, zone.name, basename, interest.name))

        dataPacket = self._getRequestedData (zone, ndn.Name (basename [len(scope):]), ndn.Name (interest.name [len(scope):]))
        self._face.put (dataPacket)

    def _getRequestedData (self, zone, basename, interestName):
        _LOG.debug (">> REAL: basename [%s], interest [%s]" % (basename, interestName))

        if str(interestName[-1])[0] == '\xFD':
            # allow version to be specified, but ignore it for the database lookup
            request_name = ndn.Name (interestName[:-1])
        else:
            request_name = interestName

        try:
            label = dns.name.from_text (ndns.dnsify (str (ndn.Name (request_name[len(basename):-1])))).relativize (origin = dns.name.root)
        except Exception, e:
            _LOG.debug ("Invalid request: label [%s] cannot be dnsified (%s)" % (request_name[len(basename):-1], e))
            return None

        if (str(interestName[-1]) == "NS"):
            msg = dns.message.Message (id=0)
            rrset = dns.rrset.from_text (label, 3600, dns.rdataclass.IN, dns.rdatatype.NS, "ns1.%s.%s" % (label, zone.dns_name.to_text ()))
            msg.answer.append (rrset)

            dataPacket = ndns.createSignedData (self._ndns,
                                                ndn.Name (interestName).appendVersion (),
                                                msg.to_wire (origin = zone.dns_name),
                                                zone.soa[0].rrs[0].ttl,
                                                # 1,
                                                zone.default_key)
        elif (str(interestName[-1]) == "FH"):
            msg = dns.message.Message (id=0)
            rrset = dns.rrset.from_text (label, 3600, dns.rdataclass.IN, dns.rdatatype.FH, "0 0 /")
            msg.answer.append (rrset)

            dataPacket = ndns.createSignedData (self._ndns,
                                                ndn.Name (interestName).appendVersion (),
                                                msg.to_wire (origin = zone.dns_name),
                                                zone.soa[0].rrs[0].ttl,
                                                # 1,
                                                zone.default_key)
        else:
            raise Exception ("NOT ACCEPTABLE REQUEST")
            
        # if (interestName[-1] == "FH"):
            
        
        # msg = dns.message.Message (id=0)
        # rrset = dns.rrset.RRset (dns.name.from_text ("@"), dns.rdataclass.IN, dns.rdatatype.NEXISTS)
        # # zone.soa[0].rrs[0].ttl
        # rrset.add (ttl = 1, rd = dns.rdtypes.IN.NEXISTS.NEXISTS (dns.rdataclass.IN, dns.rdatatype.NEXISTS))
        # msg.answer.append (rrset)

        # dataPacket = ndns.createSignedData (self._ndns,
        #                                     ndn.Name (interestName).appendVersion (),
        #                                     msg.to_wire (origin = zone.dns_name),
        #                                     zone.soa[0].rrs[0].ttl,
        #                                     # 1,
        #                                     zone.default_key)

        # print dataPacket.name
        # print msg.to_text ()
        
        # _LOG.debug ("<< Requested record nor more specific record exists. Returning NEXISTS as part of [%s]" % dataPacket.name)
        return dataPacket
