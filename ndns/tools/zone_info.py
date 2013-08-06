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
import dns.rdtypes.IN.NDNCERT
import ndns
import ndn
from StringIO import StringIO

def zone_info (args, out = None):
    if out is None:
        out = StringIO()
    
    _ndns = ndns.ndns_session (args.data_dir)

    try:
        zone_ndn = ndn.Name (args.zone)
        zone_dns = dns.name.from_text (ndns.dnsify (args.zone))
    except NameError as e:
        sys.stderr.write ("ERROR: %s\n\n" % e)
        parser.print_help ()
        exit (1)

    zone = _ndns.query (ndns.Zone).filter (ndns.Zone.has_name (zone_ndn)).first ()
    if not zone:
        sys.stderr.write ("ERROR: zone [%s] is not configured\n" % zone_ndn)
        exit (1)

    out.write (";; Origin: %s (%s)\n" % (zone_dns, zone_ndn))
    ksk = True
    for key in zone.keys:
        out.write (";; ");
        if key.key_type == "KSK":
            if args.zsk:
                continue

            out.write ("KSK [%s]\n" % key.name)
            if not key.parent_zone is None:
                out.write (";; the following record should be in [%s] zone\n" % key.parent_zone)

                ndncert = dns.rdtypes.IN.NDNCERT.NDNCERT (dns.rdataclass.IN, dns.rdatatype.NDNCERT,
                                                          key.public_key (_ndns.keydir).publicToDER ())

                out.write ("%s %s %s   %s\n" % (key.parent_label,
                                                dns.rdataclass.to_text (ndncert.rdclass), 
                                                dns.rdatatype.to_text (ndncert.rdtype), 
                                                ndncert.to_text ()))
            else:
                out.write (";;      This key is stored outside NDNS\n")
            
        else:
            if args.ksk:
                break

            if ksk:
                out.write ("\n;; Available ZSKs for the zone (default marked with *)\n;; ")
                ksk = False
            
            if key == zone.default_key:
                out.write ("* ");

            out.write ("[%s]\n" % key.name)
            
            rrset = key.rrset
            rr = rrset.rrs[0]
            out.write ("%s %d %s %s   %s\n" % (rrset.dns_label,
                                               rr.ttl,
                                               dns.rdataclass.to_text (rrset.rclass), 
                                               dns.rdatatype.to_text (rrset.rtype), 
                                               rr.dns_rrdata.to_text ()))
    

    if isinstance (out, StringIO):
        return str (out.getvalue())
