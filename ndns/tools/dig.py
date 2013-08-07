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

import ndn
import dns.rdataclass, dns.rdatatype, dns.rdata, dns.rrset, dns.zone

import ndns
from StringIO import StringIO

def dig (args, out = None):
    if out is None:
        out = StringIO ()
    
    zone = ndn.Name (args.zone)

    if args.simple:
        if args.name:
            if not args.ndn:
                args.name = ndns.ndnify (args.name)
            name = ndn.Name (args.name)
        elif not args.raw:
            sys.stderr.write ("ERROR: For simple query, ``name'' (label) argument is mandatory\n")
            exit (5)

    face = ndn.Face ()
    loop = ndn.EventLoop (face)
    needrun = True

    def onResult (result, msg):
        if not args.quiet:
            out.write (";; Got data packet [%s]\n" % result.name)
            out.write (";;       signed by [%s]\n" % result.signedInfo.keyLocator.keyName)
            out.write ("\n")
            out.write ("%s\n" % msg.to_text ())
        else:
            for rrset in msg.answer:
                out.write ("%s\n" % rrset.to_text ())

        needrun = False
        loop.stop ()

    def onError (errmsg, *k, **kw):
        out.write (";; %s\n" % errmsg)
        needrun = False
        loop.stop ()

    if args.simple:
        if not args.raw:
            ndns.CachingQueryObj.expressQueryFor (face,
                                                  onResult, onError,
                                                  zone, args.fh, name, args.rrtype)
        else:
            ndns.CachingQueryObj.expressQueryForRaw (face,
                                                     onResult, onError,
                                                     zone, hint = args.fh)
    elif args.zone_fh_query:
        ndns.CachingQueryObj.expressQueryForZoneFh (face, onResult, onError, zone)
    else:
        args.rrtype = args.name
        ndns.CachingQueryObj.expressQuery (face, onResult, onError, zone, args.rrtype)

    if needrun:
        loop.run ()

    if isinstance (out, StringIO):
        return out.getvalue ()
