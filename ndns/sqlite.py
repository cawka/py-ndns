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

import db
import sqlite3
# , iscpy
# import cStringIO
# import ndn
# import dns.rrset
# import dns.message
# from ndn import _ndn
# import time
# import sys
# from dnsifier import *

class sqlite (db):
    __slots__ = ["_db"]

    def __init__ (self, zonedb):
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
CREATE INDEX rrs_rrset_id_rrdata 
  ON rrs (rrset_id, rrdata);
CREATE TRIGGER rrs_update
BEFORE INSERT ON rrs
FOR EACH ROW
BEGIN
    DELETE FROM rrs WHERE rrset_id = NEW.rrset_id AND rrdata = NEW.rrdata;
END;
    ''');
            self._db.commit ()
        except:
            pass

        self._db.isolation_level = "DEFERRED"
        self._db.execute ("BEGIN TRANSACTION");

    def __del__ (self):
        self._db.commit ()
        self._db.close ()

    def getZone (self, name):
        c = self._db.cursor ()
        c.execute ("SELECT * FROM zones WHERE zones.name = ?", [name])
        return c.fetchone ()

    def getZones (self):
        c = self._db.cursor ()
        for row in c.execute ("SELECT * FROM zones ORDER BY name"):
            yield row

#     def createZone (self, zone_name):
#         c = self._db.cursor ()
#         c.execute ("INSERT INTO zones (name) VALUES(?)", [buffer (zone_name.get_ccnb ())])
#         return c.lastrowid

#     def destroyZone (self, zone_id):
#         c = self._db.cursor ()
#         c.execute ("DELETE FROM zones WHERE id = ?", [zone_id])

#     def listRrSets (self, zone_id):
#         c = self._db.cursor ()
#         for rrset in c.execute ("SELECT id, label, class, type, ndndata FROM rrsets WHERE zone_id = ?", [zone_id]):
#             co = ndn.ContentObject.from_ccnb (rrset[4])
#             # print co.content
#             msg = dns.message.from_wire (co.content)
#             yield {"id": rrset[0], "rrset":msg.answer[0], "data":co, "label":rrset[1]}

#     def countRrSets (self, zone_id, label):
#         c = self._db.cursor ()
#         if not isinstance(label, dns.name.Name):
#             label = dns.name.from_text (label).relativize (dns.name.root)

#         c.execute ("SELECT count(*) FROM rrsets WHERE zone_id = ? AND label = ?",
#                    [zone_id, label.to_text ()])
#         return c.fetchone ()[0]

#     def findRrSets (self, zone_id, label):
#         c = self._db.cursor ()
#         if not isinstance(label, dns.name.Name):
#             label = dns.name.from_text (label).relativize (dns.name.root)

#         for rrset in c.execute ("SELECT id, label, class, type, ndndata FROM rrsets WHERE zone_id = ? AND label = ?",
#                                 [zone_id, label.to_text ()]):
#             co = ndn.ContentObject.from_ccnb (rrset[4])
#             msg = dns.message.from_wire (co.content)
#             yield {"id":rrset[0], "rrset":msg.answer[0], "data":co}
        
#     def findRrSet (self, zone_id, label, rtype, parseDnsMessage = True):
#         c = self._db.cursor ()
#         if not isinstance(label, dns.name.Name):
#             label = dns.name.from_text (label).relativize (dns.name.root)

#         if isinstance(rtype, basestring):
#             rtype = dns.rdatatype.from_text (rtype)

#         c.execute ("SELECT id, label, class, type, ndndata FROM rrsets WHERE zone_id = ? AND label = ? AND class = ? AND type = ?",
#                    [zone_id, label.to_text (), dns.rdataclass.IN, rtype])
#         row = c.fetchone ()
#         if not row:
#             return None
        
#         co = ndn.ContentObject.from_ccnb (row[4])
#         if parseDnsMessage:
#             msg = dns.message.from_wire (co.content)
#             return {"id":row[0], "rrset":msg.answer[0], "data":co}
#         else:
#             return {"id":row[0], "data":co}

#     def findRdata (self, zone_id, label, rdata):
#         if not isinstance(label, dns.name.Name):
#             label = dns.name.from_text (label).relativize (dns.name.root)
        
#         c = self._db.cursor ()
#         c.execute ('''
# SELECT 
#     rrset.id, label, class, type, rrs.id 
#     FROM (SELECT * 
#             FROM rrsets 
#             WHERE zone_id = ? AND label = ? AND class = ? AND type = ?) rrset
#         JOIN rrs ON rrset.id = rrs.rrset_id
#     WHERE rrdata = ?''',
#                    [zone_id, label.to_text (), dns.rdataclass.IN, rdata.rdtype, buffer (rdata.to_digestable ())])

#         row = c.fetchone ()
#         if not row:
#             return None

#         return {"rrset_id":row[0], "rr_id":row[4], "rrdata":rdata}

#     def addRR (self, zone_id, label, ttl, rdata):
#         c = self._db.cursor ()
#         if not isinstance(label, dns.name.Name):
#             label = dns.name.from_text (label).relativize (dns.name.root)

#         try:
#             # find or create RRset
#             c.execute ('''SELECT id FROM rrsets WHERE zone_id = ? AND label = ? AND class = ? AND type = ?''',
#                        [zone_id, label.to_text (), rdata.rdclass, rdata.rdtype])
#             row = c.fetchone ()
#             if row:
#                 rrset_id = row[0]
#             else:
#                 c.execute ("INSERT INTO rrsets (zone_id, label, class, type) VALUES (?, ?, ?, ?)",
#                            [zone_id, label.to_text (), rdata.rdclass, rdata.rdtype])
#                 rrset_id = c.lastrowid

#             ##

#             if (dns.rdatatype.is_singleton (rdata.rdtype)):
#                 c.execute ("DELETE FROM rrs WHERE rrset_id = ?", [rrset_id])

#             c.execute ("INSERT INTO rrs (rrset_id, ttl, rrdata) VALUES (?, ?, ?)",
#                        [rrset_id, ttl, buffer (rdata.to_digestable ())])
            
#             self._signRrSet (rrset_id)
#             self._db.commit ()
#         except:
#             self._db.rollback ()
#             raise

#     def _signRrSet (self, rrset_id):
#         c = self._db.cursor ()
#         c.execute ('''SELECT name,label,class,type FROM rrsets JOIN zones on zones.id = rrsets.zone_id 
#                              WHERE rrsets.id = ?''', [rrset_id])
#         row = c.fetchone ()
#         if row:
#             rdclass = row[2]
#             rdtype = row[3]
#             zone_name = ndn.Name (ccnb_buffer = row[0])
#             zone_origin = dns.name.from_text (dnsify (str (zone_name)))

#             label = dns.name.from_text (row[1]).relativize (origin = dns.name.root)
#         else:
#             raise Error ("Non-existing RR set")
            
#         key = ndn.Key.getDefaultKey ()
#         keyLocator = ndn.KeyLocator.getDefaultKeyLocator ()
    
#         rrset = dns.rrset.RRset (label, rdclass, rdtype)
#         ttl = -1
#         for row in c.execute ("SELECT ttl,rrdata FROM rrs WHERE rrset_id = ? ORDER BY rrdata", [rrset_id]):
#             rrset.add (ttl = row[0], rd = dns.rdata.from_wire (rdclass, rdtype, row[1], 0, len (row[1])))
#             if (ttl == -1 or row[0] < ttl):
#                 ttl = row[0]

#         rrset_name = ndn.Name (zone_name)
#         rrset_name = rrset_name.append ("dns")
#         if (len (label) > 0):
#             rrset_name = rrset_name.append (label.to_text ())
#         rrset_name = rrset_name.append (dns.rdatatype.to_text (rdtype))
        
#         signedInfo = ndn.SignedInfo (key_digest = key.publicKeyID, key_locator = keyLocator, 
#                                        freshness = ttl)
#         # , py_timestamp = time.mktime (time.gmtime()))
    
#         msg = dns.message.Message (id=0)
#         # msg.origin = zone_origin
#         msg.answer.append (rrset)

#         co = ndn.ContentObject (name = rrset_name, signed_info = signedInfo, content = msg.to_wire (origin = zone_origin))

#         # print zone_origin
#         # print msg.to_wire ()
#         # print msg.to_wire (origin = zone_origin)
#         co.sign (key)
    
#         c.execute ("UPDATE rrsets SET ndndata = ? WHERE id = ?", [buffer(co.get_ccnb ()), rrset_id])

            
#     def rmAll (self, zone_id, label):
#         if not isinstance(label, dns.name.Name):
#             label = dns.name.from_text (label).relativize (dns.name.root)

#         countRrSets = self.countRrSets (zone_id, label)
#         if (countRrSets == 0):
#             return 0; # don't need to do anything special
            
#         c = self._db.cursor ()
#         c.execute ("DELETE FROM rrsets WHERE zone_id = ? AND label = ?",
#                    [zone_id, label.to_text ()])

#         return countRrSets

#     def rmRrSet (self, zone_id, label, rdtype):
#         if not isinstance(label, dns.name.Name):
#             label = dns.name.from_text (label).relativize (dns.name.root)

#         if isinstance(rdtype, basestring):
#             rtype = dns.rdatatype.from_text (rdtype)

#         rrset = self.findRrSet (zone_id, label, rdtype)
#         if not rrset:
#             return False

#         c = self._db.cursor ()
#         c.execute ("DELETE FROM rrsets WHERE zone_id = ? AND id = ?", [zone_id, rrset['id']])
#         return True

#     def rmRR (self, zone_id, label, ttl, rdata):
#         if not isinstance(label, dns.name.Name):
#             label = dns.name.from_text (label).relativize (dns.name.root)

#         rr = self.findRdata (zone_id, label, rdata)
#         if not rr:
#             return False

#         c = self._db.cursor ()
#         c.execute ("DELETE FROM rrs WHERE rrset_id = ? AND id = ?", [rr['rrset_id'], rr['rr_id']])
        
#         c.execute ("SELECT count(*) FROM rrs WHERE rrset_id = ?", [rr['rrset_id']])
#         if (c.fetchone ()[0] == 0):
#             c.execute ("DELETE FROM rrsets WHERE zone_id = ? AND id = ?", [zone_id, rr['rrset_id']])
#         else:
#             self._signRrSet (rr['rrset_id'])

#         return True
