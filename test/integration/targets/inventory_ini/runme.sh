#!/usr/bin/env bash

set -eux

ansible-playbook -v -i inventory.ini test_ansible_become.yml

ansible-inventory -v -i inventory.ini --list 2> out
test "$(grep -c 'SyntaxWarning' out)" -eq 0

# test incomplete ini inventory is an error by default
ansible-inventory -i partial.ini --list 2> out
grep out -e 'No inventory was parsed'
grep out -e 'includes undefined group: childgroup'

ANSIBLE_INI_UNRESOLVED_REFERENCE=warn ansible-inventory -i partial.ini --list >out 2>err
test "$(grep -c 'No inventory was parsed' err)" -eq 0
grep err -e 'includes undefined group: childgroup'
grep out -e 'parentgroup' && grep out -e 'childgroup' && grep out -e 'othergroup'

ANSIBLE_INI_UNRESOLVED_REFERENCE=ignore ansible-inventory -i partial.ini --list >out 2>err
test "$(grep -c 'No inventory was parsed' err)" -eq 0
test "$(grep -c 'includes undefined group: childgroup' err)" -eq 0
grep out -e 'parentgroup' && grep out -e 'childgroup' && grep out -e 'othergroup'
