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

def __clean (name):
    """
    Remove ccnx:/ and any leading or trailing slashes
    """
    if name.lower ().startswith ("ccnx:"):
        name = name[5:]
    elif name[0] != '/':
        raise NameError ('Not a valid NDN name')

    return name.strip ("/ \t")

def __dns_split (name, ltrim, rtrim):
    components = []

    # first split based on slashes
    split1 = __clean (name).split ('/')
    split1 = split1[ltrim:len(split1)-rtrim]

    # second split based on periods ".", and reversing the order of components
    for component in reversed (split1):
        # print component
        split2 = component.split (".")
        components.extend (split2)

    return components

def dnsify (ndnName, ltrim = 0, rtrim = 0, invert = False):
    if ndnName == "":
        return "."

    components = __dns_split (ndnName, ltrim, rtrim)
    if not invert:
        dnsFormattedName = ".".join (components)
    else:
        dnsFormattedName = ".".join (reversed (components))

    # conversion to utf-8 and then idna will ensure that converted name can be DNSified
    return dnsFormattedName.decode ('utf-8').encode ('idna')


def ndnify (dnsName):
    ndnName = ndn.Name ()
    for component in reversed (dnsName.split (".")):
        ndnName = ndnName.append (str (component))

    return ndnName
