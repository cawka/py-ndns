
class ZoneDoesnExist (Exception):
    """NDNS exception"""
    pass

import pyccn

from sqlalchemy import Table, MetaData, Column, ForeignKey, Integer, String, Binary, UniqueConstraint
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.declarative import declarative_base
Base = declarative_base()
from sqlalchemy.ext.hybrid import hybrid_property


class Zone (Base):
    __tablename__ = "zones"
    rrsets = relationship ("RRSet", backref="zones")

    id = Column (Integer, primary_key = True)
    _name = Column ("name", Binary, index=True, unique=True)

    @hybrid_property
    def name (self):
        return pyccn.Name (ccnb_buffer = self._name)

    @name.setter
    def name (self, value):
        self._name = value.get_ccnb ()

class RRSet (Base):
    __tablename__ = "rrsets"
    rrs = relationship ("RR", backref="rrsets")

    id = Column (Integer, primary_key = True)
    zone_id = Column (Integer, ForeignKey ("zones.id", onupdate="CASCADE", ondelete="CASCADE"))
    label = Column (String)
    rclass = Column (Integer)
    rtype = Column (Integer)
    _ndndata = Column ("ndndata", Binary)
    
    zone_id_label_rclass_rtype = UniqueConstraint ("zone_id", "label", "rclass", "rtype")

    @hybrid_property
    def ndndata (self):
        return pyccn.ContentObject.from_ccnb (self._ndndata)

    @ndndata.setter
    def ndndata (self, ndndata):
        self._ndndata = None

class RR (Base):
    __tablename__ = "rrs"

    id = Column (Integer, primary_key = True)
    rrset_id = Column (Integer, ForeignKey ("rrsets.id", onupdate="CASCADE", ondelete="CASCADE"))
    ttl = Column (Integer)
    _rrdata = Column ("rrdata", Binary)

    @hybrid_property
    def rrdata (self):
        return self._rrdata

    @rrdata.setter
    def rrdata (self, value):
        self._rrdata = value

from sqlalchemy import create_engine
engine = create_engine('sqlite:///:memory:')
engine.echo = True

Base.metadata.create_all(engine) 
Base.metadata.create_all(engine) 

