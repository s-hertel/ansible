#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: validate_role_arguments
short_description: validate that the role variables match the argument spec
description:
  - This module validates that the available role variables match the argument spec for the role entry point.
  - Variables from dependencies are included.
version_added: '2.11'
author: Ansible Core Team
options:
  name:
    description:
      - The name of the role to load.
  tasks_from:
    description:
      - The task entry point for the role. This indicates which entry in meta/arguments_spec.yml is used for validation.
    default: main
  vars_from:
    description:
      - The variable entry point for the role. This determines which file in vars/ is used to load variables.
    default: main
  defaults_from:
    description:
      - The defaults entry point for the role. This determines which file in defaults/ is used to load default variables.
    default: main
'''

EXAMPLES = r'''
- name: validate general use case for a role
  validate_role_arguments:
    name: myrole

- name: validate alternate entry point with alternate vars and defaults files
  validate_role_arguments:
    name: myrole
    tasks_from: alternate
    vars_from: alternate
    defaults_from: alternate
'''
