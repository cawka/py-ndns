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

import sqlite3, iscpy
import cStringIO
import pyccn
import dns.rrset
from pyccn import _pyccn

class ndns:
    __slots__ = ["_config", "_db"]

    def __init__ (self, config = "etc/ndns.conf"):
        self._config = config

        conf = iscpy.ParseISCString (open(self._config).read ())
        zonedb = conf['options']['zonedb'].strip ("\"'");
        self._db = sqlite3.connect (zonedb)
    
        self._db.execute ('''PRAGMA foreign_keys = ON;''')

        try:
            self._db.executescript ('''
    CREATE TABLE zones (
      id    INTEGER NOT NULL PRIMARY KEY, 
      name blob NOT NULL UNIQUE);
    CREATE TABLE rrsets (
      id       INTEGER NOT NULL PRIMARY KEY, 
      zone_id integer(10) NOT NULL, 
      label   text NOT NULL, 
      class   integer(10) NOT NULL, 
      type    integer(10) NOT NULL, 
      ndndata blob, 
      FOREIGN KEY(zone_id) REFERENCES zones(id) ON UPDATE Cascade ON DELETE Cascade);
    CREATE TABLE rrs (
      id        INTEGER NOT NULL PRIMARY KEY, 
      rrset_id integer(10) NOT NULL, 
      ttl      integer(10) NOT NULL, 
      rrdata   blob NOT NULL, 
      FOREIGN KEY(rrset_id) REFERENCES rrsets(id) ON UPDATE Cascade ON DELETE Cascade);
    CREATE UNIQUE INDEX rrsets_zone_id_label_class_type 
      ON rrsets (zone_id, label, class, type);
    CREATE INDEX rrs_rrset_id 
      ON rrs (rrset_id);
    ''');
            self._db.commit ()
        except:
            pass

    def __del__ (self):
        self._db.commit ()
        self._db.close ()


    def doesZoneExists (self, zone_name):
        c = self._db.cursor ()
        c.execute ("SELECT id FROM zones WHERE zones.name = ?", [buffer (zone_name.get_ccnb ())])
        row = c.fetchone ()
        return None if not row else row[0]

    def createZone (self, zone_name):
        c = self._db.cursor ()
        c.execute ("INSERT INTO zones (name) VALUES(?)", [buffer (zone_name.get_ccnb ())])
        return c.lastrowid

    def destroyZone (self, zone_id):
        c = self._db.cursor ()
        c.execute ("DELETE FROM zones WHERE id = ?", [zone_id])

    def addRR (self, zone_id, label, ttl, rdata):
        c = self._db.cursor ()
        
        # find or create RRset
        c.execute ('''SELECT id,name FROM rrsets JOIN zones on zones.id = rrsets.zone_id 
                         WHERE zone_id = ? AND label = ? AND class = ? AND type = ?''',
                   [zone_id, label, rdata.rdclass, rdata.rdtype])
        row = c.fetchone ()
        if row:
            rrset_id = row[0]
            zone_name = pyccn.Name (ccn_data = buffer (row[1]))
        else:
            c.execute ("INSERT INTO rrsets (zone_id, label, class, type) VALUES (?, ?, ?, ?)",
                       [zone_id, label, rdata.rdclass, rdata.rdtype])
            rrset_id = c.lastrowid

            c.execute ('''SELECT name FROM zones WHERE id = ?''', [zone_id])
            zone_name = pyccn.Name (ccn_data = r.fetchone ()[0])

        ##

        rdata_wire = cStringIO.StringIO ()
        rdata.to_wire (rdata_wire)

        c.execute ("INSERT INTO rrs (rrset_id, ttl, rrdata) VALUES (?, ?, ?)",
                   [rrset_id, ttl, buffer (rdata_wire.getvalue ())])
        rr_id = c.lastrowid
        
        key = pyccn.Key.getDefaultKey ()
        keyLocator = pyccn.KeyLocator.getDefaultKeyLocator ()

        rrset = dns.rrset.RRset (dns.name.from_text (label), rdata.rdclass, rdata.rdtype)
        for row in c.execute ("SELECT ttl,rrdata FROM rrs WHERE rrset_id = ? ORDER BY rrdata", [rrset_id]):
            rrset.add (ttl = row[0], rd = dns.rdata.from_wire (rdata.rdclass, rdata.rdtype, row[1], 0, len (row[1])))

        # print rrset.to_text (relativize=False)

        # NDN name
        rrset_ndn_name = 
        pyccn.ContentObject ()
