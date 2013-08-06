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

from sqlalchemy import Table, MetaData, Column, ForeignKey, Integer, Binary, Enum, UniqueConstraint
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.hybrid import hybrid_property, hybrid_method
import os

from ndns import Base
from dnsifier import *

class KeyException (Exception):
    """
    Exception raised when there is a problem with key
    """
    pass

class Key (Base):
    """
    Key abstraction:

    .. code-block:: sql

        CREATE TABLE keys (
            id INTEGER NOT NULL,
            zone_id INTEGER,
            name BLOB,
            parent_zone BLOB,
            key_type VARCHAR(3) NOT NULL, /* "KSK", "ZKS", "DZSK" */
            rrset_id INTEGER,
            PRIMARY KEY (id),
            FOREIGN KEY(zone_id) REFERENCES zones (id) ON DELETE CASCADE ON UPDATE CASCADE,
            CHECK (key_type IN ('KSK', 'ZKS', 'DZSK'))
        );
        CREATE INDEX ix_keys_zone_id ON keys (zone_id);
        CREATE UNIQUE INDEX ix_keys_name ON keys (name);

    In addition to database entry, this class manages RSA keys (private and public) on disk: several
    methods require explicit location of the folder where private/public key are stored or should be
    stored.

    Note that the current implementation does not provide any protection of private keys and they are
    stored in non-encrypted form.

    Whenever requested, the key (:py:class:`ndn.Key`) will be loaded and cached.

    :ivar rrset: One-to-one relationship (shortcut) to :py:class:`ndns.rrset.RRSet` data
    :ivar zone: Back-reference to the :py:class:`ndns.zone.Zone` to which the key belongs
    """
    __tablename__ = "keys"

    id = Column (Integer, primary_key = True)
    zone_id = Column (Integer, ForeignKey ("zones.id", onupdate="CASCADE", ondelete="CASCADE"), index=True)
    _name = Column ("name", Binary, index=True, unique=True)
    _parent_zone = Column ("parent_zone", Binary) # only makes sense for KSKs

    key_type = Column (Enum ("KSK", "ZKS", "DZSK"), nullable=False, default="ZSK")
    # DZSK: dynamic-zone signing key

    rrset_id = Column (Integer)
    rrset = relationship ("RRSet",
                          uselist=False, post_update=True,
                          primaryjoin="Key.rrset_id == RRSet.id",
                          foreign_keys="Key.rrset_id",
                          remote_side="RRSet.id")

    _key = None

    @property
    def name (self):
        """Get :py:class:`ndn.Name` object from internally stored wire format of the key name"""
        return ndn.Name.fromWire (self._name)

    @property
    def parent_zone (self):
        """
        Get :py:class:`ndn.Name` object from internaly stored wire format of the parent's zone name where key belongs

        Note that this property makes sense only for certain KSKs, other keys belong to the zone itself
        """

        if self._parent_zone:
            return ndn.Name.fromWire (self._parent_zone)
        else:
            return None

    @property
    def label (self):
        """
        Get DNS label of the key name

        Note that this method makes sense only for ZSKs.  For KSKs, use :py:attr:`parent_label`.

        :returns: DNS formatted string of key name minus the zone name
        :rtype: str
        """

        name = self.name
        if name[:len(self.zone.name)] == self.zone.name:
            return dnsify (str (ndn.Name (name[len(self.zone.name) + 1 : -1])))
        else:
            raise KeyException ("Key does not belong to the zone (KSK should be stored in the parent zone!)")

    @property
    def ndn_label (self):
        """
        Get label of the key name

        Note that this method makes sense only for ZSKs

        :returns: Key name minus the zone name
        :rtype: :py:class:`ndn.Name`
        """
        name = self.name
        if name[:len(self.zone.name)] == self.zone.name:
            return ndn.Name (name[len(self.zone.name) + 1 : -1])
        else:
            raise KeyException ("Key does not belong to the zone (KSK should be stored in the parent zone!)")

    @property
    def parent_label (self):
        """
        Get DNS label of the key, seen from the parent zone

        Note that this method makes sense only KSKs.  For ZSKs use :py:attr:`label`.

        :returns: DNS formatted string of key name minus the parent's zone name
        :rtype: str
        """

        if self.key_type != "KSK":
            raise KeyException ("Key.parent_label makes sense only for KSK keys")

        if self.parent_zone is None:
            raise KeyException ("Parent zone is not set (key is stored outside NDNS)")

        name = self.name
        if name[:len(self.parent_zone)] == self.parent_zone:
            return dnsify (str (ndn.Name (name[len(self.parent_zone) + 1 : -1])))
        else:
            raise KeyException ("Key does not belong to the parent zone")

    @property
    def local_key_id (self):
        """Get local (unique) identifier of the key that can be used as part of the file name"""
        return dnsify (str (ndn.Name (self.name[:-1])), invert = True)

    @hybrid_method
    def has_name (self, other):
        return self._name == other.toWire ()

    @name.setter
    def name (self, value):
        """Facilitate SQL comparison with another zone name in wire format"""
        self._name = buffer (value.toWire ())

    @parent_zone.setter
    def parent_zone (self, value):
        """Set parent zone name to the wire representation of the value

        :type  :value: ndn.Name
        :param :value: zone name
        """
        self._parent_zone = buffer (value.toWire ())

    def generate (self, keydir, password = None):
        '''
        Generate key pair on disk

        The generated key (both private and public) will be internally cached and returned
        for subsequent access to :py:attr:`private_key` or :py:attr:`public_key`.

        :param keydir: Key directory
        :type keydir: str
        :param password: Password with which private key is encrypted
        :type password: str
        '''

        self._key = ndn.Key ()
        # self._key.generateRSA (2048 if self.key_type == "KSK" else 1024)
        self._key.generateRSA (512)

        if not os.path.exists (keydir):
            os.makedirs (keydir)

        local_key_id = self.local_key_id

        if os.path.exists ("%s/%s.pub" % (keydir, local_key_id)):
            raise KeyException ("Key already exists (%s/%s.pub), to re-generate the key, delete it manually" % (keydir, local_key_id))

        if os.path.exists ("%s/%s.pri" % (keydir, local_key_id)):
            raise KeyException ("Key already exists (%s/%s.pri), to re-generate the key, delete it manually" % (keydir, local_key_id))

        self._key.publicToPEM ("%s/%s.pub" % (keydir, local_key_id))
        self._key.privateToPEM ("%s/%s.pri" % (keydir, local_key_id), password = password)

    def erase (self, keydir):
        if not os.path.exists (keydir):
            return

        try:
            os.unlink ("%s/%s.pub" % (keydir, self.local_key_id))
            os.unlink ("%s/%s.pri" % (keydir, self.local_key_id))
        except:
            pass

    def load_default_key (self):
        """
        Load host's default key and key locator (from ``~/.ccnx/.ccnx_keystore`` and ``~/.ccnx/.ccnx_keystore.pubcert``)
        """
        self._key = ndn.Key.getDefault ()
        self.name = ndn.KeyLocator.getDefault ().keyName

    def load_from_pubkey (self, pubkey):
        """
        Create public key from the supplied string

        :type pubkey: str
        :param pubkey: Public key in PEM format
        """
        self._key = ndn.Key ()
        self._key.fromPEM (pubkey)

    @property
    def key_locator (self):
        return ndn.KeyLocator (self.name)

    def private_key (self, keydir, password = None):
        """
        Get :py:class:`ndn.Key` containing private key

        Name of the key file is automatically determined based on the key and zone name.

        The loaded key (both private and public) will be internally cached and returned
        for subsequent accesses.

        :param keydir: Key directory
        :type keydir: str
        :param password: Password with which private key is encrypted
        :type password: str
        :return: :py:class:`ndn.Key`
        """
        if not self._key:
            self._key = ndn.Key ()
            self._key.fromPEM ("%s/%s.pri" % (keydir, self.local_key_id), password = password)

        return self._key

    def public_key (self, keydir):
        """
        Get :py:class:`ndn.Key` containing public key

        Name of the key file is automatically determined based on the key and zone name.

        The loaded key (only public) will be internally cached and returned for subsequent accesses.

        :param keydir: Key directory
        :type keydir: str
        :return: :py:class:`ndn.Key`
        """
        if not self._key:
            key = ndn.Key ()
            key.fromPEM ("%s/%s.pub" % (keydir, self.local_key_id))
            return key

        return self._key
