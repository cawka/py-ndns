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

class NDNAUTH(dns.rdata.Rdata):
    """NDNAUTH record

    @ivar zoneName: NDN name of the authoritative zone
    @type zoneName: pyccn.Name object"""

    __slots__ = ['zoneName']

    def __init__(self, rdclass, rdtype, zoneName):
        super(NDNAUTH, self).__init__(rdclass, rdtype)
        self.zoneName = zoneName

    def to_text(self, **kw):
        return '%s' % (self.zoneName)

    def from_text(cls, rdclass, rdtype, tok, origin = None, relativize = True):
        zoneName = pyccn.Name (tok.get_string())
        tok.get_eol()
        return cls(rdclass, rdtype, zoneName)

    from_text = classmethod(from_text)

    def to_wire(self, file, compress = None, origin = None):
        file.write(self.zoneName.get_ccnb())

    def from_wire(cls, rdclass, rdtype, wire, current, rdlen, origin = None):
        zoneName = pyccn.Name (ccnb_buffer = wire[current : current + rdlen])
        return cls(rdclass, rdtype, zoneName)

    from_wire = classmethod(from_wire)

    def _cmp(self, other):
        return cmp(self.zoneName, other.zoneName)
