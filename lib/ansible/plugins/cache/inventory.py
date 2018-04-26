#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
'''


import os
from ansible.errors import AnsibleError
from ansible.plugins.cache import BaseCacheModule
from ansible.plugins.loader import cache_loader


class InventoryFileCacheModule(BaseCacheModule):
    def __init__(self, plugin_name, timeout, cache_dir):
        self._cache_dir = self._get_cache_connection(cache_dir)
        self._timeout = timeout

        self.plugin_name = plugin_name
        self._plugin = self.get_plugin(plugin_name)

    def get(self, cache_key):
        self._plugin.get(cache_key)

    def set(self, cache_key, value):
        self._plugin.set(cache_key, value)

    def keys(self):
        return self._plugin.keys()

    def contains(self, cache_key):
        return self._plugin.contains(cache_key)

    def delete(self, cache_key):
        return self._plugin.delete(cache_key)

    def flush(self):
        return self._plugin.flush()

    def copy(self):
        return self._plugin.copy()

    def _load(self, path):
        self._plugin.load(path)

    def _dump(self, value, path):
        return self._plugin._dump(value, path)

    def get_plugin(self, plugin_name):
        plugin = cache_loader.get(plugin_name, _uri=self._cache_dir, _timeout=self._timeout)
        if not plugin:
            raise AnsibleError('Unable to load the facts cache plugin (%s).' % (plugin_name))
        self._cache = {}
        return plugin

    def _get_cache_connection(self, source):
        if source:
            try:
                return os.path.expanduser(os.path.expandvars(source))
            except TypeError:
                pass
