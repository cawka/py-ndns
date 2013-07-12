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

class db:
    def selectZoneId (self, zone_name):
        """
        Select zone id by zone_name
        @param zone_name: Zone name
        @type  zone_name: buffer
        @rtype: int
        """

        raise NotImplementedError

    def selectAllZones (self):
        """
        Return all configured zones
        @rtype: iterator
        """

        raise NotImplementedError

    def createZone (self, zone_name):
        raise NotImplementedError

    def destroyZone (self, zone_id):
        raise NotImplementedError
