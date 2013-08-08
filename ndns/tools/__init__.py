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

class Params (object):
    def __init__ (self, **kwargs):
        for param in kwargs:
            self.__setattr__ (param, kwargs.get (param))

    def __getattr__ (self, name):
        return None

