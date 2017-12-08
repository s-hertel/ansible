# (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# Make coding more python3-ish
from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
    cache: inventoryplugin
    short_description: Hosts generated from an inventory plugin
    description:
        - This cache uses JSON formatted, per inventory plugin, files saved to the filesystem.
    version_added: "2.5"
    author: Ansible Core
    options:
      _uri:
        required: True
        description:
          - Path in which the cache plugin will save the inventory files
        type: list
        env:
          - name: ANSIBLE_CACHE_PLUGIN_CONNECTION
        ini:
          - key: fact_caching_connection
            section: defaults
      _prefix:
        description: User defined prefix to use when creating the inventory files
        env:
          - name: ANSIBLE_CACHE_PLUGIN_PREFIX
        ini:
          - key: fact_caching_prefix
          - section: defaults
      _timeout:
        default: 86400
        description: Expiration timeout for the cache plugin data
        env:
          - name: ANSIBLE_CACHE_PLUGIN_TIMEOUT
        ini:
          - key: fact_caching_timeout
            section: defaults
        type: integer
'''

import codecs

try:
    import simplejson as json
except ImportError:
    import json

from ansible.plugins.cache.jsonfile import CacheModule as JsonCache
from ansible.plugins.inventory import Cacheable

class CacheModule(JsonCache, Cacheable):
    """
    A caching module backed by json files.
    """
    #def _load(self, filepath):
    #    with codecs.open(filepath, 'r', encoding='utf-8') as f:
    #        return json.load(f)

    def _dump(self, value, filepath):
        with codecs.open(filepath, 'w', encoding='utf-8') as f:
            f.write(value)
