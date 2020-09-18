#!/usr/bin/env bash

set -eux

export ANSIBLE_COLLECTIONS_PATHS=$PWD/collections

ansible-playbook -i ../../inventory test_collection_action_groups.yml "$@"
