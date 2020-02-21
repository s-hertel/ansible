# Copyright: (c) 2019, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os

import ansible.constants as c
from ansible.module_utils.six import string_types
from ansible.parsing.dataloader import DataLoader
from ansible.playbook.attribute import FieldAttribute
from ansible.utils.collection_loader import AnsibleCollectionLoader


def _ensure_default_collection(collection_list=None):
    default_collection = AnsibleCollectionLoader().default_collection

    if collection_list is None:
        collection_list = []

    if default_collection:  # FIXME: exclude role tasks?
        if isinstance(collection_list, string_types):
            collection_list = [collection_list]

        if default_collection not in collection_list:
            collection_list.insert(0, default_collection)

    # if there's something in the list, ensure that builtin or legacy is always there too
    if collection_list and 'ansible.builtin' not in collection_list and 'ansible.legacy' not in collection_list:
        collection_list.append('ansible.legacy')

    return collection_list


def _pre_load_action_groups():
    action_groups = {}
    for path in c.COLLECTIONS_PATHS:
        # There's a bug ending collection paths with ansible_collections anyway, so this if should be true for the time being
        if not os.path.split(path)[-1] == 'ansible_collections':
            path = os.path.join(path, 'ansible_collections')
        if not os.path.isdir(path):
            continue
        for collection_namespace in os.listdir(path):
            for collection_name in os.listdir(os.path.join(path, collection_namespace)):
                action_groups_path = os.path.join(path, collection_namespace, collection_name, 'meta', 'action_groups.yml')
                if not os.path.isfile(action_groups_path):
                    continue
                with open(action_groups_path, 'r') as config_def:
                    action_group_config = DataLoader().load(config_def)
                    action_groups['%s.%s' % (collection_namespace, collection_name)] = action_group_config
    return action_groups


class CollectionSearch:

    # this needs to be populated before we can resolve tasks/roles/etc
    _collections = FieldAttribute(isa='list', listof=string_types, priority=100, default=_ensure_default_collection)
    _action_groups = FieldAttribute(isa='dict', default=_pre_load_action_groups)

    def _load_collections(self, attr, ds):
        # this will only be called if someone specified a value; call the shared value
        _ensure_default_collection(collection_list=ds)

        if not ds:  # don't return an empty collection list, just return None
            return None

        return ds
