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

import dns.zone
import sqlite3

#################

LOCAL_HINT = pyccn.Name ("/ndn/ucla.edu")

FOLDER = "zones/"
ZONES = [
    "ndnsim.net"
    ]
#################

# don't try to read zone file, query only when somebody has requested it

class AuthoritativeDns:
    __slots__ = ["zone"]
    
    def __init__ (self, folder, zone):
        pass

# def auth_response ():
#     print ("hello")

DNS = {}

for zone in ZONES:
    DNS[zone] = AuthoritativeDns (zone)

# Make this module usable as a script too.
if __name__ == '__main__':
    import sys
    import traceback

    # zonefile = open("zones/test-zone.txt", 'rb')

    # # Parse the zones
    # try:
    #     zone = dns.zone.from_file(zonefile, origin = 'ndnsim.net')
    # except dns.exception.DNSException:
    #     traceback.print_exc()

    # zone.to_file (sys.stdout, relativize=False, sorted=False)

    # sys.exit(0)

    auth_response ()
