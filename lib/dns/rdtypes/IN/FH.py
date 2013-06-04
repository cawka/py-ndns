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

class FH(dns.rdata.Rdata):
    """FH record

    @ivar priority: the priority
    @type priority: int
    @ivar weight: the weight
    @type weight: int
    @ivar hint: the target host
    @type hint: pyccn.Name object"""

    __slots__ = ['priority', 'weight', 'hint']

    def __init__(self, rdclass, rdtype, priority, weight, hint):
        super(FH, self).__init__(rdclass, rdtype)
        self.priority = priority
        self.weight = weight
        self.hint = hint

    def to_text(self, **kw):
        return '%d %d %s' % (self.priority, self.weight, self.hint)

    def from_text(cls, rdclass, rdtype, tok, origin = None, relativize = True):
        priority = tok.get_uint16()
        weight = tok.get_uint16()
        hint = pyccn.Name (tok.get_string())
        if len(hint.get_ccnb ()) > 255:
            raise dns.exception.SyntaxError("forwarding hint is too long")
        tok.get_eol()
        return cls(rdclass, rdtype, priority, weight, hint)

    from_text = classmethod(from_text)

    def to_wire(self, file, compress = None, origin = None):
        two_ints = struct.pack("!HH", self.priority, self.weight)
        file.write(two_ints)
        file.write(self.hint.get_ccnb())

    def from_wire(cls, rdclass, rdtype, wire, current, rdlen, origin = None):
        (priority, weight) = struct.unpack('!HH',
                                           wire[current : current + 4])
        current += 4
        rdlen -= 4
        
        hint = pyccn.Name (ccnb_buffer = wire[current : current + rdlen])
        return cls(rdclass, rdtype, priority, weight, hint)

    from_wire = classmethod(from_wire)

    def _cmp(self, other):
        sp = struct.pack("!HH", self.priority, self.weight)
        op = struct.pack("!HH", other.priority, other.weight)
        v = cmp(sp, op)
        if v == 0:
            v = cmp(self.hint, other.hint)
        return v
