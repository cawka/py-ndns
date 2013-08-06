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

import sys
import dns.rdataclass
import dns.rdatatype
import dns.rdata
import dns.rrset
import dns.zone
import ndns
import ndn

def add (args):
    _ndns = ndns.ndns_session (args.data_dir)

    try:
        zone_ndn = ndn.Name (args.zone)
        zone_dns = ndns.dnsify (args.zone)
    except NameError as e:
        sys.stderr.write ("ERROR: %s\n\n" % e)
        parser.print_help ()
        exit (1)

    zone = _ndns.query (ndns.Zone).filter (ndns.Zone.has_name (zone_ndn)).first ()
    if not zone:
        sys.stderr.write ("ERROR: zone [%s] is not configured\n" % zone_ndn)
        exit (1)

    origin = dns.name.from_text (zone_dns)

    if args.rr:
        zonefile = dns.zone.from_text (args.rr, origin = origin, check_origin = False)
    else:
        zonefile = dns.zone.from_file (sys.stdin, origin = origin, check_origin = False)
    
    default_rtt = zone.soa[0].rrs[0].ttl

    for (name, ttl, rdata) in zonefile.iterate_rdatas ():
        if ttl == 0:
            ttl = default_rtt

        print "Create record: '%s %s %d %s'" % (name, dns.rdatatype.to_text (rdata.rdtype), ttl, rdata.to_text ())
        rrset = ndns.add_rr (_ndns, zone, origin, name, ttl, rdata)
        rrset.refresh_ndndata (_ndns, zone.default_key)

    if getattr (args, 'commit', True):
        _ndns.commit ()
