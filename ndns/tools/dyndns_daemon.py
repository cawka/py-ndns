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
from ndns.policy.identity import *
import dns.rdtypes.IN.NDNAUTH
import dns.rdtypes.IN.NEXISTS
import dns.rdtypes.IN.NDNCERTSEQ

_LOG = logging.getLogger ("dyndns.Daemon")

class DyndnsDaemon (object):
#public:
    def __init__ (self, data_dir, session, face):
        self.data_dir = data_dir
        self.session = session
        self._face = face # ndn.Face () # this should not be necessary...

    def _processDyNDNS (self, zone, basename, interest):
        zone = self.session.query (ndns.Zone).filter_by (id = zone.id).first ()

        for update in interest.name[len(basename):-1]:
            try:
                dataPacket = ndn.ContentObject.fromWire (update)
                _LOG.debug ("Processing %s" % dataPacket.name)
                
                if dataPacket.name[:len(basename)] != basename[:]:
                    _LOG.warn ("Record [%s] does not belong to the zone" % dataPacket.name)
                    continue

                if not ndns.TrustPolicy.verify (dataPacket):
                    _LOG.warn ("Data [%s] packet cannot be verified" % dataPacket.name)
                    continue

                seqno = ndn.Name ().append (dataPacket.name[-1])
                label = dns.name.from_text (ndns.dnsify (str (ndn.Name (dataPacket.name[len(basename):-2])))).relativize (origin = dns.name.root)
                rtype = dataPacket.name[-2]

                if not self._authorizeKey (zone, basename, dataPacket.signedInfo.keyLocator.keyName, seqno):
                    _LOG.warn ("UPDATE is signed with unrecognizeable key [%s]" % dataPacket.signedInfo.keyLocator.keyName)
                    continue

                _LOG.info ("DyNDNS update authorized: [%s]" % dataPacket.name)
                msg = dns.message.from_wire (dataPacket.content)
                
                if dns.opcode.from_flags (msg.flags) == dns.opcode.UPDATE:
                    count = 0

                    extra_msg = ""
                    for dns_update in msg.authority:
                        if not dns_update.deleting or len(dns_update.items) != 0:
                            _LOG.warn ("Only delete update is allowed in this way")
                            extra_msg = "%s\n%s" % (extra_msg, "Only delete update is allowed in this way")
                            continue

                        if dns_update.rdtype == dns.rdatatype.ANY:
                            _LOG.warn ("Not supported update type: [%s]" % dns_update)
                            extra_msg = "%s\n%s" % (extra_msg, "Only delete RRset update is allowed")
                            continue

                        if dns_update.rdtype == dns.rdatatype.NDNCERTSEQ:
                            _LOG.warn ("NDNCERTSEQ cannot be updated remotely")
                            extra_msg = "%s\n%s" % (extra_msg, "NDNCERTSEQ cannot be updated remotely")
                            continue

                        label = dns_update.name.relativize (zone.dns_name)
                        rtype = dns.rdatatype.to_text (dns_update.rdtype)

                        for rrset in self.session.query (ndns.RRSet).\
                                with_parent (zone).\
                                filter_by (label = label.to_text (), rclass = dns_update.rdclass, rtype = dns_update.rdtype):
                            _LOG.debug ("Deleting [%s]" % rrset.ndndata.name)
                            self.session.delete (rrset)
                            count += 1

                    self.session.commit ()
                    result = ndns.createSignedData (self.session, interest.name.appendVersion (), "OK: Deleted %d RR sets%s" % (count, extra_msg), 1, zone.default_key)
                    self._face.put (result)
                else:
                    dns_rrset = msg.answer[0]
                    rrset = self.session.query (ndns.RRSet).\
                        with_parent (zone).\
                        filter_by (label = label.to_text (), rclass = dns_rrset.items[0].rdclass, rtype = dns_rrset.items[0].rdtype).\
                        first ()
                    
                    if not rrset:
                        rrset = ndns.RRSet (zone = zone, 
                                            label = label.to_text (), 
                                            rclass = dns_rrset.items[0].rdclass, rtype = dns_rrset.items[0].rdtype, 
                                            ndndata = dataPacket)
                    else:
                        rrset.rrs = []
                        rrset.ndndata = dataPacket
                    
                    for rdata in dns_rrset.items:
                        rr = ndns.RR (rrset = rrset, ttl = dns_rrset.ttl, rrdata = rdata)
                    
                    self.session.commit ()
                    
                    result = ndns.createSignedData (self.session, interest.name.appendVersion (), "OK", 1, zone.default_key)
                    self._face.put (result)

            except Exception, e:
                _LOG.warn ("Undecodeable component in DyNDNS update: [%s]" % update)
                _LOG.warn ("%s" % e)
                continue
            
    def _authorizeKey (self, zone, basename, keyName, seqno):
        if (keyName[-1] != "NDNCERT"):
            return False

        key_label = dns.name.from_text (ndns.dnsify (str (ndn.Name (keyName[len(basename):-1])))).\
            relativize (origin = dns.name.root)

        key = self.session.query (ndns.RRSet).with_parent (zone).filter_by (label = key_label.to_text (), rtype = dns.rdatatype.NDNCERT).first ()
        if not key:
            _LOG.warn ("Key [%s] has been validated, but does not belong to the zone. Denying update" % keyName)
            return False
        
        current_key_seq = self.session.query (ndns.RRSet).with_parent (zone).filter_by (label = key_label.to_text (), rtype = dns.rdatatype.NDNCERTSEQ).first ()
        
        if not current_key_seq:
            current_key_seq = ndns.RRSet (label = key_label.to_text (), zone = zone, rclass = dns.rdataclass.IN, rtype = dns.rdatatype.NDNCERTSEQ)
            rd = dns.rdtypes.IN.NDNCERTSEQ.NDNCERTSEQ (rdclass = dns.rdataclass.IN, rdtype = dns.rdatatype.NDNCERTSEQ, seq = ndn.Name ())
            rr = ndns.RR (ttl = 0, rrdata = rd, rrset = current_key_seq)

        if current_key_seq.rrs[0].dns_rrdata.seq >= seqno:
            _LOG.warn ("Replay attack detected, denying the update with sequence number [%s]" % seqno)
            return False

        updated_rr = current_key_seq.rrs[0].dns_rrdata
        updated_rr.seq = seqno
        current_key_seq.rrs[0].rrdata = updated_rr
        current_key_seq.refresh_ndndata (self.session, zone.default_key)
        self.session.commit ()

        return True
