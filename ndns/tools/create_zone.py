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
import time
import os
import dns.rdataclass
import dns.rdatatype
import dns.rdata
import dns.rrset
import dns.rdtypes.IN.NDNCERT
import ndns
import ndn

def create_zone (args):
    _ndns = ndns.ndns_session (args.data_dir)

    try:
        zone_ndn = ndn.Name (args.zone)
        zone_dns = ndns.dnsify (args.zone)
    except NameError as e:
        sys.stderr.write ("ERROR: %s\n\n" % e)
        parser.print_help ()
        exit (1)

    if zone_dns != "":
        mname = args.mname if (args.mname[-1] == '.') else "%s.%s." % (args.mname, zone_dns)
        rname = args.rname if (args.rname[-1] == '.') else "%s.%s." % (args.rname, zone_dns)
    else:
        mname = args.mname if (args.mname[-1] == '.') else "%s." % (args.mname)
        rname = args.rname if (args.rname[-1] == '.') else "%s." % (args.rname)

    # zone = _ndns.query (ndns.Zone).filter (ndns.Zone.has_name (zone_ndn)).first ()
    # if zone:
    #     sys.stderr.write ("ERROR: zone [%s] already configured\n" % zone_ndn)
    #     sys.stderr.write ("       If you want to recrecrete the zone, delete it first using `ndn-destroy-zone` command\n")
    #     exit (1)

    zone = ndns.Zone (name = zone_ndn)

    ##########################
    #   Create ZSK and KSK   #
    ##########################

    if args.default_ksk:
        ksk = ndns.Key (key_type = "KSK")
        ksk.load_default_key ()
        if (args.ksk_id):
            ksk.name = ndn.Name (args.ksk_id)
        zone.keys.append (ksk)
    else:
        ksk_name = ndn.Name (zone_ndn[:-1]).append ("DNS")
        for component in ndns.ndnify (zone_ndn[-1]):
            ksk_name = ksk_name.append (component)

        if (args.ksk_id):
            ksk_name = ksk_name.append ("ksk-%s" % args.ksk_id)
        else:
            ksk_name = ksk_name.append ("ksk-%d" % int (time.time ()))

        ksk_name = ksk_name.append ("NDNCERT")

        ksk = ndns.Key (key_type = "KSK",
                        name = ksk_name,
                        parent_zone = ndn.Name (zone_ndn[:-1]))
        ksk.generate (_ndns.keydir)
        zone.keys.append (ksk)

    zsk_name = zone_ndn.append ("DNS")
    if (args.zsk_id):
        zsk_name = zsk_name.append ("zsk-%s" % args.zsk_id)
    else:
        zsk_name = zsk_name.append ("zsk-%d" % int (time.time ()))
    zsk_name = zsk_name.append ("NDNCERT")
    
    zsk = ndns.Key (key_type="ZKS", name = zsk_name)
    zsk.generate (_ndns.keydir)
    zone.keys.append (zsk)

    rrset = ndns.RRSet (label = zsk.label, rclass = dns.rdataclass.IN, rtype = dns.rdatatype.NDNCERT)
    zone.rrsets.append (rrset)

    rr = ndns.RR (ttl = args.ttl)
    rrset.rrs.append (rr)

    ndncert = dns.rdtypes.IN.NDNCERT.NDNCERT (dns.rdataclass.IN, dns.rdatatype.NDNCERT,
                                              zsk.public_key (_ndns.keydir).publicToDER ())
    rr.rrdata = ndncert

    zsk.rrset = rrset
    zone.default_key = zsk

    key_rrset = rrset
    key_rrset.refresh_ndndata (_ndns, ksk)
    
    ###########################
    #    Create SOA record    #
    ###########################

    rrset = ndns.RRSet (label = "@", rclass = dns.rdataclass.IN, rtype = dns.rdatatype.SOA)
    zone.rrsets.append (rrset)

    rr = ndns.RR (ttl = args.ttl)
    rrset.rrs.append (rr)

    serial  = time.mktime (time.gmtime())
    refresh = args.ttl
    retry   = args.ttl
    expire  = args.ttl
    minimum = args.ttl

    soa = dns.rdata.from_text (dns.rdataclass.IN, dns.rdatatype.SOA,
                               "%s %s ( %d %d %d %d %d )" % (mname, rname, serial, refresh, retry, expire, minimum))
    rr.rrdata = soa

    rrset.refresh_ndndata (_ndns, zsk)

    _ndns.add (zone)
    
    if getattr (args, 'commit', True):
        _ndns.commit ()
