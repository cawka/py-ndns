# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-
#
# Copyright (c) 2013 University of California, Los Angeles
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation;
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
# Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>


# Copyright (C) 2003-2007, 2009-2011 Nominum, Inc.
#
# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose with or without fee is hereby granted,
# provided that the above copyright notice and this permission notice
# appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NOMINUM DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NOMINUM BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import struct

import dns.exception
import dns.rdata
import dns.name
import pyccn

import base64


class NDNCERT(dns.rdata.Rdata):
    """NDNCERT record

    @ivar cert: bits of NDN certificate
    @type cert: DER encoded bits of NDN certificate (e.g., bits of public key)"""

    __slots__ = ['cert']

    def __init__(self, rdclass, rdtype, cert):
        super(NDNCERT, self).__init__(rdclass, rdtype)
        self.cert = cert

    def to_text(self, **kw):
        return '%s' % (base64.b64encode (self.cert))

    def from_text(cls, rdclass, rdtype, tok, origin = None, relativize = True):
        cert = base64.b64decode (tok.get_string())

        # Not sure if there is a limit...
        # if len(cert) > 255:
        #     raise dns.exception.SyntaxError("cert is too long")
        tok.get_eol()
        return cls(rdclass, rdtype, cert)

    from_text = classmethod(from_text)

    def to_wire(self, file, compress = None, origin = None):
        file.write(self.cert)

    def from_wire(cls, rdclass, rdtype, wire, current, rdlen, origin = None):
        cert = wire[current : current + rdlen]
        return cls(rdclass, rdtype, cert)

    from_wire = classmethod(from_wire)

    def _cmp(self, other):
        return cmp (self.cert, other.cert)
