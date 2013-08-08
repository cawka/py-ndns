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

from dyndns_daemon import DyndnsDaemon
import logging
import ndn
import dns.rdataclass, dns.rdatatype, dns.rdata, dns.rrset, dns.zone
import os, functools

# part of lib/
import ndns
from ndns.policy.identity import *
import dns.rdtypes.IN.NDNAUTH
import dns.rdtypes.IN.NEXISTS
import dns.rdtypes.IN.NDNCERTSEQ

_LOG = logging.getLogger ("ndns.Daemon")

class NdnsDaemon (object):
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

        if self._enable_dyndns:
            self._dyndns = DyndnsDaemon (self.data_dir, self._ndns, self._face)

        self._startZoneServing ()

        self._eventLoop = ndn.EventLoop (self._face)
        self._eventLoop.run ()

        _LOG.info ('Daemon stopped')

    def terminate (self):
        self._stopZoneServing ()
        self._eventLoop.stop ()
        self._face = None
        self._ndns = None

    def reloadConfig (self):
        _LOG.info ('Reload zone information')
        self._stopZoneServing ()
        self._startZoneServing ()

    def updateLocalPrefix (self, oldPrefix, newPrefix):
        _LOG.info ("Update local prefix from [%s] to [%s]" % (oldPrefix, newPrefix))
        self._eventLoop.execute (functools.partial (self._updateLocalPrefix_Execute, newPrefix))

#private:
    def _updateLocalPrefix_Execute (self, newPrefix):
        self._stopZoneServing ()
        self._autoScope = [ newPrefix ]
        self._startZoneServing ()

    def _enableZone (self, zone):
        name = zone.name

        self._face.setInterestFilter (name.append ("DNS"),
                                      functools.partial (self._onRequest, ndn.Name (), zone))

        activeScopes = []
        for scope in self._scopes + self._autoScope:
            if not scope.isPrefixOf (name):
                activeScopes.append (str (scope))
                self._face.setInterestFilter (scope.append ("\xF0.").append (name).append ("DNS"),
                                              functools.partial (self._onRequest, scope.append ("\xF0."), zone))
        _LOG.info ('>> Start serving zone [%s] (%s)' % (name, activeScopes))

    def _disableZone (self, zone):
        name = zone.name

        self._face.clearInterestFilter (name.append ("DNS"))

        activeScopes = []
        for scope in self._scopes + self._autoScope:
            if not scope.isPrefixOf (name):
                activeScopes.append (str (scope))
                self._face.clearInterestFilter (scope.append ("\xF0.").append (name).append ("DNS"))

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

        if self._enable_dyndns:
            if interest.name[-1] == "NDNUPDATE":
                self._dyndns._processDyNDNS (zone, basename, interest)
                return

        dataPacket = self._getRequestedData (zone, ndn.Name (basename [len(scope):]), ndn.Name (interest.name [len(scope):]))
        if dataPacket:
            if len (scope) == 0:
                self._face.put (dataPacket)
            else:
                # will sign with real key, but not sure if it is really necessary
                encapPacket = ndns.createSignedData (self._ndns,
                                                     scope.append (dataPacket.name),
                                                     dataPacket.toWire (),
                                                     dataPacket.signedInfo.freshnessSeconds,
                                                     zone.default_key)
                _LOG.debug ("Encapsulating into [%s]" % encapPacket.name)
                self._face.put (encapPacket)

        return

    def _getRequestedData (self, zone, basename, interestName):
        _LOG.debug (">> REAL: basename [%s], interest [%s]" % (basename, interestName))

        if str(interestName[-1])[0] == '\xFD':
            # allow version to be specified, but ignore it for the database lookup
            request_name = ndn.Name (interestName[:-1])
        else:
            request_name = interestName

        try:
            rrtype = dns.rdatatype.from_text (str(request_name[-1]))
        except Exception, e:
            _LOG.debug ("Invalid request: unknown or unrecognized RR type [%s] (%s)" % (request_name[-1], e))
            return None

        try:
            label = dns.name.from_text (ndns.dnsify (str (ndn.Name (request_name[len(basename):-1])))).relativize (origin = dns.name.root)
        except Exception, e:
            _LOG.debug ("Invalid request: label [%s] cannot be dnsified (%s)" % (request_name[len(basename):-1], e))
            return None

        rrset = self._ndns.query (ndns.RRSet).with_parent (zone).filter_by (label = label.to_text (), rtype = rrtype).first ()

        if not rrset:
            # check if there is more a specific record:
            more_specific_rrset = self._ndns.query (ndns.RRSet).\
                with_parent (zone).\
                filter (ndns.RRSet.label.like ("%%.%s" % label.to_text ()), ndns.RRSet.rtype == rrtype).first ()
            if more_specific_rrset:

                msg = dns.message.Message (id=0)
                rrset = dns.rrset.RRset (zone.dns_name, dns.rdataclass.IN, dns.rdatatype.NDNAUTH)
                # zone.soa[0].rrs[0].ttl
                rrset.add (ttl = 1, rd = dns.rdtypes.IN.NDNAUTH.NDNAUTH (dns.rdataclass.IN, dns.rdatatype.NDNAUTH, zone.name))
                msg.authority.append (rrset)

                dataPacket = ndns.createSignedData (self._ndns,
                                                    interestName.appendVersion (),
                                                    msg.to_wire (origin = zone.dns_name),
                                                    # zone.soa[0].rrs[0].ttl,
                                                    1,
                                                    zone.default_key)

                _LOG.debug ("<< Requested record doesn't exist, but there is a more specific record. Returning NDNAUTH as [%s]" % dataPacket.name)
                return dataPacket
            else:
                # _LOG.debug ("(!!! no action defined yet!!!) The requested record (%s %s) not found in zone [%s]" %
                #             (label.to_text (), dns.rdatatype.to_text (rrtype), zone.name))

                msg = dns.message.Message (id=0)
                rrset = dns.rrset.RRset (label, dns.rdataclass.IN, dns.rdatatype.NEXISTS)
                # zone.soa[0].rrs[0].ttl
                rrset.add (ttl = 1, rd = dns.rdtypes.IN.NEXISTS.NEXISTS (dns.rdataclass.IN, dns.rdatatype.NEXISTS))
                msg.answer.append (rrset)

                dataPacket = ndns.createSignedData (self._ndns,
                                                    interestName.appendVersion (),
                                                    msg.to_wire (origin = zone.dns_name),
                                                    # zone.soa[0].rrs[0].ttl,
                                                    1,
                                                    zone.default_key)

                _LOG.debug ("<< Requested record nor more specific record exists. Returning NEXISTS as part of [%s]" % dataPacket.name)
                return dataPacket

        dataPacket = rrset.ndndata
        if not interestName.isPrefixOf (dataPacket.name):
            _LOG.debug ("Request is not in a canonical form (e.g., case mistmatch), requested data found, but cannot be returned")
            _LOG.debug ("        Could be version mistmatch")
            return None
        else:
            _LOG.debug ("<< Found a valid record, returning data object [%s]" % dataPacket.name)
            return dataPacket
