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
import sys
from StringIO import StringIO

def dig (args, out = None, cachingQuery = None, policy = None):
    if out is None:
        out = StringIO ()

    if policy is None:
        policy = ndns.TrustPolicy

    if cachingQuery is None:
        cachingQuery = ndns.CachingQueryObj

    if not isinstance (args.zone, ndn.Name):
        zone = ndn.Name (args.zone)
    else:
        zone = args.zone

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
        if args.no_output:
            needrun = False
            loop.stop ()
            return

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
        if args.no_output:
            needrun = False
            loop.stop ()
            return

        out.write (";; %s\n" % errmsg)
        needrun = False
        loop.stop ()

    def onPreResult (result, msg):
        def _onVerify (data, status):
            if status:
                onResult (result, msg)
            else:
                onError ("Got answer, but it cannot be verified")

        if args.verify:
            onResult (result, msg)
        else:
            policy.verifyAsync (face, result, _onVerify)

    if args.simple:
        if not args.raw:
            cachingQuery.expressQueryFor (face,
                                                  onPreResult, onError,
                                                  zone, args.fh, name, args.rrtype, verify = args.verify)
        else:
            cachingQuery.expressQueryForRaw (face,
                                                     onPreResult, onError,
                                                     zone, hint = args.fh, verify = args.verify)
    elif args.zone_fh_query:
        cachingQuery.expressQueryForZoneFh (face, onPreResult, onError, zone, args.verify)
    else:
        args.rrtype = args.name
        cachingQuery.expressQuery (face, onPreResult, onError, zone, args.rrtype, args.verify)

    if needrun:
        loop.run ()

    if isinstance (out, StringIO):
        return out.getvalue ()
