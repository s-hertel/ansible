# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Dependency structs."""
# FIXME: add caching all over the place

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os
from collections import namedtuple
from glob import iglob
from keyword import iskeyword  # used in _is_fqcn

try:
    from typing import TYPE_CHECKING
except ImportError:
    TYPE_CHECKING = False

if TYPE_CHECKING:
    from typing import Tuple

import yaml

from ansible.errors import AnsibleError
from ansible.module_utils._text import to_bytes, to_native, to_text
from ansible.module_utils.six.moves.urllib.parse import urlparse
from ansible.module_utils.six import raise_from


try:  # NOTE: py3/py2 compat
    # FIXME: put somewhere into compat
    _is_py_id = str.isidentifier  # type: ignore  # py2 mypy can't deal with it
except AttributeError:  # Python 2
    # FIXME: port this to AnsibleCollectionRef.is_valid_collection_name
    from re import match as _match_pattern
    from tokenize import Name as _VALID_IDENTIFIER_REGEX
    _valid_identifier_string_regex = ''.join((_VALID_IDENTIFIER_REGEX, r'\Z'))

    def _is_py_id(tested_str):
        # Ref: https://stackoverflow.com/a/55802320/595220
        return bool(_match_pattern(_valid_identifier_string_regex, tested_str))


_ALLOW_CONCRETE_POINTER_IN_SOURCE = False  # NOTE: This is a feature flag
_GALAXY_YAML = b'galaxy.yml'
_MANIFEST_JSON = b'MANIFEST.json'


def _is_collection_src_dir(dir_path):
    b_dir_path = to_bytes(dir_path, errors='surrogate_or_strict')
    return os.path.isfile(os.path.join(b_dir_path, _GALAXY_YAML))


def _is_installed_collection_dir(dir_path):
    b_dir_path = to_bytes(dir_path, errors='surrogate_or_strict')
    return os.path.isfile(os.path.join(b_dir_path, _MANIFEST_JSON))


def _is_collection_dir(dir_path):
    return (
        _is_installed_collection_dir(dir_path) or
        _is_collection_src_dir(dir_path)
    )


def _find_collections_in_subdirs(dir_path):
    b_dir_path = to_bytes(dir_path, errors='surrogate_or_strict')
    galaxy_yml_glob_pattern = os.path.join(
        b_dir_path,
        # b'*',  # namespace is supposed to be top-level per spec
        b'*',  # collection name
        _GALAXY_YAML,
    )
    return (
        os.path.dirname(galaxy_yml)
        for galaxy_yml in iglob(galaxy_yml_glob_pattern)
    )


def _is_collection_namespace_dir(tested_str):
    return any(_find_collections_in_subdirs(tested_str))


def _is_file_path(tested_str):
    return os.path.isfile(to_bytes(tested_str, errors='surrogate_or_strict'))


def _is_http_url(tested_str):
    return urlparse(tested_str).scheme.lower() in {'http', 'https'}


def _is_git_url(tested_str):
    return tested_str.startswith(('git+', 'git@'))


def _is_concrete_artifact_pointer(tested_str):
    return any(
        predicate(tested_str)
        for predicate in (
            # NOTE: Maintain the checks to be sorted from light to heavy:
            _is_git_url,
            _is_http_url,
            _is_file_path,
            _is_collection_dir,
            _is_collection_namespace_dir,
        )
    )


def _is_fqcn(tested_str):
    # FIXME: port this to AnsibleCollectionRef.is_valid_collection_name
    if tested_str.count('.') != 1:
        return False

    return all(
        # FIXME: keywords and identifiers are different in differnt Pythons
        not iskeyword(ns_or_name) and _is_py_id(ns_or_name)
        for ns_or_name in tested_str.split('.')
    )


class _ComputedReqKindsMixin:

    @classmethod
    def from_dir_path_as_unknown(cls, dir_path):
        if os.path.isdir(dir_path):
            return cls.from_dir_path_implicit(dir_path)
        raise AnsibleError("The collection directory '{0}' doesn't exist".format(dir_path))

    @classmethod
    def from_dir_path_as_dev(cls, dir_path, art_mgr):
        if _is_collection_src_dir(dir_path):
            return cls.from_dir_path(dir_path, art_mgr)

        raise AnsibleError(
            '`{path!s}` must be an installed collection directory. It '
            'does not appear to have a {file_name!s}. A '
            '{file_name!s} is expected if the collection will be '
            'built and installed via ansible-galaxy.'.
            format(path=dir_path, file_name='galaxy.yml'),
        )

    @classmethod
    def from_dir_path_as_installed(cls, dir_path, art_mgr):
        if _is_installed_collection_dir(dir_path):
            return cls.from_dir_path(dir_path, art_mgr)

        raise AnsibleError(
            '`{path!s}` must be an installed collection directory. It '
            'does not appear to have a {manifest_name!s}. A '
            '{manifest_name!s} is expected if the collection has been '
            'built and installed via ansible-galaxy.'.
            format(
                path=to_native(dir_path),
                manifest_name=to_native(_MANIFEST_JSON),
            ),
        )

    @classmethod
    def from_dir_path(cls, dir_path, art_mgr):
        b_dir_path = to_bytes(dir_path, errors='surrogate_or_strict')
        if not _is_collection_dir(b_dir_path):
            raise ValueError(
                '`dir_path` argument must be an installed or a source'
                ' collection directory.',
            )

        tmp_inst_req = cls(None, None, dir_path, 'dir')
        req_name = art_mgr.get_direct_collection_fqcn(tmp_inst_req)
        req_version = art_mgr.get_direct_collection_version(tmp_inst_req)

        return cls(req_name, req_version, dir_path, 'dir')

    @classmethod
    def from_dir_path_implicit(cls, dir_path):
        # There is no metadata, but it isn't required for a functional collection. Determine the namespace.name from the path.
        path_list = to_text(dir_path, errors='surrogate_or_strict').split(os.path.sep)
        req_name = '%s.%s' % (path_list[-2], path_list[-1])
        req_version = '*'
        return cls(req_name, req_version, dir_path, 'dir')

    @classmethod
    def from_string(cls, collection_input, artifacts_manager):
        req = {}
        if _is_concrete_artifact_pointer(collection_input):
            # Arg is a file path or URL to a collection
            req['name'] = collection_input
        else:
            req['name'], _sep, req['version'] = collection_input.partition(':')
            if not req['version']:
                del req['version']

        return cls.from_requirement_dict(req, artifacts_manager)

    @classmethod
    def from_requirement_dict(cls, collection_req, art_mgr):
        req_name = collection_req.get('name', None)
        req_version = collection_req.get('version', '*')
        req_type = collection_req.get('type')
        # TODO: decide how to deprecate the old src API behavior
        req_source = collection_req.get('source', None)

        if req_type is None:
            if (  # FIXME: decide on the future behavior:
                    _ALLOW_CONCRETE_POINTER_IN_SOURCE
                    and req_source is not None
                    and _is_concrete_artifact_pointer(req_source)
            ):
                src_path = req_source
            elif (
                    req_name is not None
                    and _is_concrete_artifact_pointer(req_name)
            ):
                src_path, req_name = req_name, None
            elif req_name is not None and _is_fqcn(req_name):
                req_type = 'galaxy'
            else:
                dir_tip_tmpl = (  # NOTE: leading LFs are for concat
                    '\n\nTip: Make sure you are pointing to the right '
                    'subdirectory — `{src!s}` looks like a directory '
                    'but it is neither a collection, nor a namespace '
                    'dir.'
                )

                if req_source is not None and os.path.isdir(req_source):
                    tip = dir_tip_tmpl.format(src=req_source)
                elif req_name is not None and os.path.isdir(req_name):
                    tip = dir_tip_tmpl.format(src=req_name)
                else:
                    tip = ''

                raise AnsibleError(  # NOTE: I'd prefer a ValueError instead
                    'Neither the collection requirement entry key '
                    "'name', nor 'source' point to a concrete "
                    "resolvable collection artifact. Also 'name' is "
                    'not an FQCN. A valid collection name must be in '
                    'the format <namespace>.<collection>. Please make '
                    'sure that the namespace and the collection name '
                    ' contain characters from [a-zA-Z0-9_] only.'
                    '{extra_tip!s}'.format(extra_tip=tip),
                )

        if req_type is None:
            if _is_git_url(src_path):
                req_type = 'git'
                req_source = src_path
            elif _is_http_url(src_path):
                req_type = 'url'
                req_source = src_path
            elif _is_file_path(src_path):
                req_type = 'file'
                req_source = src_path
            elif _is_collection_dir(src_path):
                req_type = 'dir'
                req_source = src_path
            elif _is_collection_namespace_dir(src_path):
                req_name = None  # No name for a virtual req or "namespace."?
                req_type = 'subdirs'
                req_source = src_path
            else:
                raise AnsibleError(  # NOTE: this is never supposed to be hit
                    'Failed to automatically detect the collection '
                    'requirement type.',
                )

        if req_type not in {'file', 'galaxy', 'git', 'url', 'dir', 'subdirs'}:
            raise AnsibleError(
                "The collection requirement entry key 'type' must be "
                'one of file, galaxy, git, dir, subdirs, or url.'
            )

        if req_name is None and req_type == 'galaxy':
            raise AnsibleError(
                'Collections requirement entry should contain '
                "the key 'name' if it's requested from a Galaxy-like "
                'index server.',
            )

        tmp_inst_req = cls(req_name, req_version, req_source, req_type)

        if req_type not in {'galaxy', 'subdirs'} and req_name is None:
            req_name = art_mgr.get_direct_collection_fqcn(tmp_inst_req)  # TODO: fix the cache key in artifacts manager?

        if req_type not in {'galaxy', 'subdirs'} and req_version == '*':
            req_version = art_mgr.get_direct_collection_version(tmp_inst_req)

        assert req_name is None or not os.path.isdir(req_name)
        return cls(
            req_name, req_version,
            req_source, req_type,
        )

    def __repr__(self):
        return (
            '<{self!s} of type {coll_type!r} from {src!s}>'.
            format(self=self, coll_type=self.type, src=self.src or 'Galaxy')
        )

    def __str__(self):
        return to_native(self.__unicode__())

    def __unicode__(self):
        if self.fqcn is None:
            return (
                u'"virtual collection Git repo"' if self.is_scm
                else u'"virtual collection namespace"'
            )

        return (
            u'{fqcn!s}:{ver!s}'.
            format(fqcn=to_text(self.fqcn), ver=to_text(self.ver))
        )

    def _get_separate_ns_n_name(self):  # FIXME: use LRU cache
        return self.fqcn.split('.')

    @property
    def namespace(self):
        if self.is_virtual:
            raise TypeError('Virtual collections do not have a namespace')

        return self._get_separate_ns_n_name()[0]

    @property
    def name(self):
        if self.is_virtual:
            raise TypeError('Virtual collections do not have a name')

        return self._get_separate_ns_n_name()[-1]

    @property
    def canonical_package_id(self):
        if not self.is_virtual:
            return to_native(self.fqcn)

        return (
            '<virtual namespace from {src!s} of type {src_type!s}>'.
            format(src=to_native(self.src), src_type=to_native(self.type))
        )

    @property
    def is_virtual(self):
        return self.is_scm or self.is_subdirs

    @property
    def is_file(self):
        # FIXME: Make the checks less dynamic assuming that the type is
        # FIXME: always set in the initializer (and is not None).
        return self.type == 'file' or (
            not self.type and
            _is_file_path(self.src)
        )

    @property
    def is_dir(self):
        return self.type == 'dir' or (
            not self.type and
            _is_collection_dir(self.src)
        )

    @property
    def namespace_collection_paths(self):
        assert self.is_subdirs, 'This property only makes sense for namespaces'
        return [
            to_native(path)
            for path in _find_collections_in_subdirs(self.src)
        ]

    @property
    def is_subdirs(self):
        return self.type == 'subdirs' or (
            not self.type and
            _is_collection_namespace_dir(self.src)
        )

    @property
    def is_url(self):
        return self.type == 'url' or (
            not self.type and
            _is_http_url(self.src)
        )

    @property
    def is_scm(self):
        return self.type == 'git' or (
            not self.type and
            _is_git_url(self.src)
        )

    @property
    def is_concrete_artifact(self):
        return any(
            getattr(self, 'is_{prop!s}'.format(prop=prop), False)
            for prop in (
                # NOTE: Maintain the checks to be sorted from light to heavy:
                'scm', 'url', 'file', 'dir', 'subdirs',
            )
        )

    @property
    def is_online_index_pointer(self):
        return not self.is_concrete_artifact


class Requirement(
        _ComputedReqKindsMixin,
        namedtuple('Requirement', ('fqcn', 'ver', 'src', 'type')),
):
    """An abstract requirement request."""


class Candidate(
        _ComputedReqKindsMixin,
        namedtuple('Candidate', ('fqcn', 'ver', 'src', 'type'))
):
    """A concrete collection candidate with its version resolved."""
