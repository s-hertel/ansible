# -*- coding: utf-8 -*-
# Copyright: (c) 2020-2021, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Dependency structs."""
# FIXME: add caching all over the place

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
from collections import namedtuple
from collections.abc import MutableSequence
from glob import iglob
from urllib.parse import urlparse
from yaml import safe_load

try:
    from typing import TYPE_CHECKING
except ImportError:
    TYPE_CHECKING = False

if TYPE_CHECKING:
    from typing import Type, TypeVar
    from ansible.galaxy.collection.concrete_artifact_manager import (
        ConcreteArtifactsManager,
    )
    Collection = TypeVar(
        'Collection',
        'Candidate', 'Requirement',
        '_ComputedReqKindsMixin',
    )


from ansible.errors import AnsibleError
from ansible.galaxy.api import GalaxyAPI
from ansible.module_utils._text import to_bytes, to_native, to_text
from ansible.module_utils.common._collections_compat import MutableMapping
from ansible.module_utils.common.arg_spec import ArgumentSpecValidator
from ansible.utils.collection_loader import AnsibleCollectionRef
from ansible.utils.display import Display


_ALLOW_CONCRETE_POINTER_IN_SOURCE = False  # NOTE: This is a feature flag
_GALAXY_YAML = b'galaxy.yml'
_MANIFEST_JSON = b'MANIFEST.json'
_SOURCE_METADATA_FILE = b'GALAXY.yml'

display = Display()


def get_validated_source_info(b_source_info_path, namespace, name, version):
    source_info_path = to_text(b_source_info_path, errors='surrogate_or_strict')

    if not os.path.isfile(b_source_info_path):
        return None

    try:
        with open(b_source_info_path, mode='rb') as fd:
            metadata = safe_load(fd)
    except OSError as e:
        display.warning(
            f"Error getting collection source information at '{source_info_path}': {to_text(e, errors='surrogate_or_strict')}"
        )
        return None

    if not isinstance(metadata, MutableMapping):
        display.warning(f"Error getting collection source information at '{source_info_path}': expected a YAML dictionary")
        return None

    schema_errors = _validate_v1_source_info_schema(namespace, name, version, metadata)
    if schema_errors:
        display.warning(f"Ignoring source metadata file at {source_info_path} due to the following errors:")
        display.warning("\n".join(schema_errors))
        display.warning("Correct the source metadata file by reinstalling the collection.")
        return None

    return metadata


def _validate_v1_source_info_schema(namespace, name, version, provided_arguments):
    argument_spec_data = dict(
        format_version=dict(choices=["1.0.0"]),
        download_url=dict(),
        version_url=dict(),
        server=dict(),
        signatures=dict(
            type=list,
            suboptions=dict(
                signature=dict(),
                pubkey_fingerprint=dict(),
                signing_service=dict(),
                pulp_created=dict(),
            )
        ),
        name=dict(choices=[name]),
        namespace=dict(choices=[namespace]),
        version=dict(choices=[version]),
    )

    if not isinstance(provided_arguments, dict):
        raise AnsibleError(
            f'Invalid offline source info for {namespace}.{name}:{version}, expected a dict and got {type(provided_arguments)}'
        )
    validator = ArgumentSpecValidator(argument_spec_data)
    validation_result = validator.validate(provided_arguments)

    return validation_result.error_messages


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

    subdir_glob_pattern = os.path.join(
        b_dir_path,
        # b'*',  # namespace is supposed to be top-level per spec
        b'*',  # collection name
    )

    for subdir in iglob(subdir_glob_pattern):
        if os.path.isfile(os.path.join(subdir, _MANIFEST_JSON)):
            yield subdir
        elif os.path.isfile(os.path.join(subdir, _GALAXY_YAML)):
            yield subdir


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


class _ComputedReqKindsMixin:

    def __init__(self, *args, **kwargs):
        if not self.may_have_offline_galaxy_info:
            self._source_info = None
        else:
            # Store Galaxy metadata adjacent to the namespace of the collection
            # Chop off the last two parts of the path (/ns/coll) to get the dir containing the ns
            b_src = to_bytes(self.src, errors='surrogate_or_strict')
            b_path_parts = b_src.split(to_bytes(os.path.sep))[0:-2]
            b_path = to_bytes(os.path.sep).join(b_path_parts)

            info_path = self.construct_galaxy_info_path(b_path)

            self._source_info = get_validated_source_info(
                info_path,
                self.namespace,
                self.name,
                self.ver
            )

    @classmethod
    def from_dir_path_as_unknown(  # type: ignore[misc]
            cls,  # type: Type[Collection]
            dir_path,  # type: bytes
            art_mgr,  # type: ConcreteArtifactsManager
    ):  # type: (...)  -> Collection
        """Make collection from an unspecified dir type.

        This alternative constructor attempts to grab metadata from the
        given path if it's a directory. If there's no metadata, it
        falls back to guessing the FQCN based on the directory path and
        sets the version to "*".

        It raises a ValueError immediatelly if the input is not an
        existing directory path.
        """
        if not os.path.isdir(dir_path):
            raise ValueError(
                "The collection directory '{path!s}' doesn't exist".
                format(path=to_native(dir_path)),
            )

        try:
            return cls.from_dir_path(dir_path, art_mgr)
        except ValueError:
            return cls.from_dir_path_implicit(dir_path)

    @classmethod
    def from_dir_path(cls, dir_path, art_mgr):
        """Make collection from an directory with metadata."""
        b_dir_path = to_bytes(dir_path, errors='surrogate_or_strict')
        if not _is_collection_dir(b_dir_path):
            display.warning(
                u"Collection at '{path!s}' does not have a {manifest_json!s} "
                u'file, nor has it {galaxy_yml!s}: cannot detect version.'.
                format(
                    galaxy_yml=to_text(_GALAXY_YAML),
                    manifest_json=to_text(_MANIFEST_JSON),
                    path=to_text(dir_path, errors='surrogate_or_strict'),
                ),
            )
            raise ValueError(
                '`dir_path` argument must be an installed or a source'
                ' collection directory.',
            )

        tmp_inst_req = cls(None, None, dir_path, 'dir', None)
        req_version = art_mgr.get_direct_collection_version(tmp_inst_req)
        try:
            req_name = art_mgr.get_direct_collection_fqcn(tmp_inst_req)
        except TypeError as err:
            # Looks like installed/source dir but isn't: doesn't have valid metadata.
            display.warning(
                u"Collection at '{path!s}' has a {manifest_json!s} "
                u"or {galaxy_yml!s} file but it contains invalid metadata.".
                format(
                    galaxy_yml=to_text(_GALAXY_YAML),
                    manifest_json=to_text(_MANIFEST_JSON),
                    path=to_text(dir_path, errors='surrogate_or_strict'),
                ),
            )
            raise ValueError(
                "Collection at '{path!s}' has invalid metadata".
                format(path=to_text(dir_path, errors='surrogate_or_strict'))
            ) from err

        return cls(req_name, req_version, dir_path, 'dir', None)

    @classmethod
    def from_dir_path_implicit(  # type: ignore[misc]
            cls,  # type: Type[Collection]
            dir_path,  # type: bytes
    ):  # type: (...)  -> Collection
        """Construct a collection instance based on an arbitrary dir.

        This alternative constructor infers the FQCN based on the parent
        and current directory names. It also sets the version to "*"
        regardless of whether any of known metadata files are present.
        """
        # There is no metadata, but it isn't required for a functional collection. Determine the namespace.name from the path.
        u_dir_path = to_text(dir_path, errors='surrogate_or_strict')
        path_list = u_dir_path.split(os.path.sep)
        req_name = '.'.join(path_list[-2:])
        return cls(req_name, '*', dir_path, 'dir', None)  # type: ignore[call-arg]

    @classmethod
    def from_string(cls, collection_input, artifacts_manager, supplemental_signatures):
        req = {}
        if _is_concrete_artifact_pointer(collection_input):
            # Arg is a file path or URL to a collection
            req['name'] = collection_input
        else:
            req['name'], _sep, req['version'] = collection_input.partition(':')
            if not req['version']:
                del req['version']
        req['signatures'] = supplemental_signatures

        return cls.from_requirement_dict(req, artifacts_manager)

    @classmethod
    def from_requirement_dict(cls, collection_req, art_mgr):
        req_name = collection_req.get('name', None)
        req_version = collection_req.get('version', '*')
        req_type = collection_req.get('type')
        # TODO: decide how to deprecate the old src API behavior
        req_source = collection_req.get('source', None)
        req_signature_sources = collection_req.get('signatures', None)
        if req_signature_sources is not None:
            if art_mgr.keyring is None:
                raise AnsibleError(
                    f"Signatures were provided to verify {req_name} but no keyring was configured."
                )

            if not isinstance(req_signature_sources, MutableSequence):
                req_signature_sources = [req_signature_sources]
            req_signature_sources = frozenset(req_signature_sources)

        if req_type is None:
            if (  # FIXME: decide on the future behavior:
                    _ALLOW_CONCRETE_POINTER_IN_SOURCE
                    and req_source is not None
                    and _is_concrete_artifact_pointer(req_source)
            ):
                src_path = req_source
            elif (
                    req_name is not None
                    and AnsibleCollectionRef.is_valid_collection_name(req_name)
            ):
                req_type = 'galaxy'
            elif (
                    req_name is not None
                    and _is_concrete_artifact_pointer(req_name)
            ):
                src_path, req_name = req_name, None
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
                elif req_name:
                    tip = '\n\nCould not find {0}.'.format(req_name)
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
                if _is_installed_collection_dir(src_path) and _is_collection_src_dir(src_path):
                    # Note that ``download`` requires a dir with a ``galaxy.yml`` and fails if it
                    # doesn't exist, but if a ``MANIFEST.json`` also exists, it would be used
                    # instead of the ``galaxy.yml``.
                    raise AnsibleError(
                        u"Collection requirement at '{path!s}' has both a {manifest_json!s} "
                        u"file and a {galaxy_yml!s}.\nThe requirement must either be an installed "
                        u"collection directory or a source collection directory, not both.".
                        format(
                            path=to_text(src_path, errors='surrogate_or_strict'),
                            manifest_json=to_text(_MANIFEST_JSON),
                            galaxy_yml=to_text(_GALAXY_YAML),
                        )
                    )
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

        if req_type != 'galaxy' and req_source is None:
            req_source, req_name = req_name, None

        if (
                req_type == 'galaxy' and
                isinstance(req_source, GalaxyAPI) and
                not _is_http_url(req_source.api_server)
        ):
            raise AnsibleError(
                "Collections requirement 'source' entry should contain "
                'a valid Galaxy API URL but it does not: {not_url!s} '
                'is not an HTTP URL.'.
                format(not_url=req_source.api_server),
            )

        tmp_inst_req = cls(req_name, req_version, req_source, req_type, req_signature_sources)

        if req_type not in {'galaxy', 'subdirs'} and req_name is None:
            req_name = art_mgr.get_direct_collection_fqcn(tmp_inst_req)  # TODO: fix the cache key in artifacts manager?

        if req_type not in {'galaxy', 'subdirs'} and req_version == '*':
            req_version = art_mgr.get_direct_collection_version(tmp_inst_req)

        return cls(
            req_name, req_version,
            req_source, req_type,
            req_signature_sources,
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

    @property
    def may_have_offline_galaxy_info(self):
        if self.fqcn is None:
            # Virtual collection
            return False
        elif not self.is_dir or self.src is None or not _is_collection_dir(self.src):
            # Not a dir or isn't on-disk
            return False
        return True

    def construct_galaxy_info_path(self, b_metadata_dir):
        if not self.may_have_offline_galaxy_info and not self.type == 'galaxy':
            raise TypeError('Only installed collections from a Galaxy server have offline Galaxy info')

        # ns.coll-1.0.0.info
        b_dir_name = to_bytes(f"{self.namespace}.{self.name}-{self.ver}.info", errors="surrogate_or_strict")

        # collections/ansible_collections/ns.coll-1.0.0.info/GALAXY.yml
        return os.path.join(b_metadata_dir, b_dir_name, _SOURCE_METADATA_FILE)

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
        return self.type == 'file'

    @property
    def is_dir(self):
        return self.type == 'dir'

    @property
    def namespace_collection_paths(self):
        return [
            to_native(path)
            for path in _find_collections_in_subdirs(self.src)
        ]

    @property
    def is_subdirs(self):
        return self.type == 'subdirs'

    @property
    def is_url(self):
        return self.type == 'url'

    @property
    def is_scm(self):
        return self.type == 'git'

    @property
    def is_concrete_artifact(self):
        return self.type in {'git', 'url', 'file', 'dir', 'subdirs'}

    @property
    def is_online_index_pointer(self):
        return not self.is_concrete_artifact

    @property
    def source_info(self):
        return self._source_info


RequirementNamedTuple = namedtuple('Requirement', ('fqcn', 'ver', 'src', 'type', 'signature_sources'))


CandidateNamedTuple = namedtuple('Candidate', ('fqcn', 'ver', 'src', 'type', 'signatures'))


class Requirement(
        _ComputedReqKindsMixin,
        RequirementNamedTuple,
):
    """An abstract requirement request."""

    def __new__(cls, *args, **kwargs):
        self = RequirementNamedTuple.__new__(cls, *args, **kwargs)
        return self

    def __init__(self, *args, **kwargs):
        super(Requirement, self).__init__()


class Candidate(
        _ComputedReqKindsMixin,
        CandidateNamedTuple,
):
    """A concrete collection candidate with its version resolved."""

    def __new__(cls, *args, **kwargs):
        self = CandidateNamedTuple.__new__(cls, *args, **kwargs)
        return self

    def __init__(self, *args, **kwargs):
        super(Candidate, self).__init__()
