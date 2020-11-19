# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Requirement resolver implementations."""

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from resolvelib import Resolver


class CollectionDependencyResolver(Resolver):
    """A dependency resolver for Ansible Collections.

    This is a proxy class allowing us to abstract away importing resolvelib
    outside of the `ansible.galaxy.dependency_resolution` Python package.
    """
