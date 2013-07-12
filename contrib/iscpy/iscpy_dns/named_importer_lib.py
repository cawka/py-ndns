#!/usr/bin/env python

# Copyright (c) 2009, Purdue University
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# Redistributions in binary form must reproduce the above copyright notice, this
# list of conditions and the following disclaimer in the documentation and/or
# other materials provided with the distribution.
#
# Neither the name of the Purdue University nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


import copy
import iscpy

def MakeNamedDict(named_string):
  """Makes a more organized named specific dict from parsed_dict

  Inputs:
    named_string: string of named file

  Outputs:
    dict: organized dict with keys views options and acls
    {'acls': {'acl1': ['10.1.0/32', '10.1.1/32']},
     'views': {'view1': {'zones': {'test_zone': {'file': '/path/to/zonefile',
                                                 'type': 'master',
                                                'options': 'zone_options'}},
                         'options': 'view_options'}}}
  """
  named_string = iscpy.ScrubComments(named_string)
  parsed_dict = copy.deepcopy(iscpy.ParseTokens(iscpy.Explode(named_string)))
  named_data = {'acls': {}, 'views': {}, 'options': {}, 'orphan_zones': {}}
  for key in parsed_dict:
    if( key.startswith('acl') ):
      named_data['acls'][key.split()[1]] = []
      for cidr in parsed_dict[key]:
        named_data['acls'][key.split()[1]].append(cidr)
    elif( key.startswith('view') ):
      view_name = key.split()[1].strip('"').strip()
      named_data['views'][view_name] = {'zones': {}, 'options': {}}
      for view_key in parsed_dict[key]:
        if( view_key.startswith('zone') ):
          zone_name = view_key.split()[1].strip('"').strip()
          named_data['views'][view_name]['zones'][zone_name] = (
              {'options': {}, 'file': ''})
          for zone_key in parsed_dict[key][view_key]:
            if( zone_key.startswith('file') ):
              named_data['views'][view_name]['zones'][zone_name]['file'] = (
                  parsed_dict[key][view_key][zone_key].strip('"').strip())
            elif( zone_key.startswith('type') ):
              named_data['views'][view_name]['zones'][zone_name]['type'] = (
                  parsed_dict[key][view_key][zone_key].strip('"').strip())
            else:
              named_data['views'][view_name]['zones'][zone_name]['options'][
                  zone_key] = parsed_dict[key][view_key][zone_key]
        else:
          named_data['views'][view_name]['options'][view_key] = (
              parsed_dict[key][view_key])
    elif( key.startswith('zone') ):
      zone_name = key.split()[1].strip('"').strip()
      named_data['orphan_zones'][zone_name] = (
          {'options': {}, 'file': ''})
      for zone_key in parsed_dict[key]:
        if( zone_key.startswith('file') ):
          named_data['orphan_zones'][zone_name]['file'] = (
              parsed_dict[key][zone_key].strip('"').strip())
        elif( zone_key.startswith('type') ):
          named_data['orphan_zones'][zone_name]['type'] = (
              parsed_dict[key][zone_key].strip('"').strip())
        else:
          named_data['orphan_zones'][zone_name]['options'][
              zone_key] = parsed_dict[key][zone_key]
    else:
      named_data['options'][key] = parsed_dict[key]

  return named_data

def MakeZoneViewOptions(named_data):
  """Makes zone and view data into strings to load into database.

  Inputs:
    named_data: named dict from MakeNamedDict

  Outputs:
    dict: dict with keys {'views': {}, 'zones': {}}
  """
  options_dict = {'views':{}, 'zones': {}}
  for view in named_data['views']:
    options_dict['views'][view] = iscpy.MakeISC(named_data['views'][view]['options'])
    for zone in named_data['views'][view]['zones']:
      options_dict['zones'][zone] = iscpy.MakeISC(named_data['views'][view]['zones'][
          zone]['options'])
  for zone in named_data['orphan_zones']:
    options_dict['zones'][zone] = iscpy.MakeISC(named_data['orphan_zones'][zone][
        'options'])
  return options_dict

def DumpNamedHeader(named_data):
  """This function dumps the named header from a named_data dict

  Inputs:
    named_data: named dict from MakeNamedDict

  Outputs:
    str: stirng of named header
  """
  return iscpy.MakeISC(named_data['options'])

def MergeOrphanZones(named_data, view):
  """Merges orphaned zones into regular zones in named_data

  Inputs:
    named_data: named dict from MakeNamedDict
    view: string of view name
  """
  for zone in named_data['orphan_zones']:
    if( view not in named_data['views'] ):
      named_data['views'][view] = {'zones': {}, 'options': {}}
    named_data['views'][view]['zones'][zone] = named_data['orphan_zones'][zone]

