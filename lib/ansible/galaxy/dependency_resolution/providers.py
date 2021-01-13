# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Requirement provider interfaces."""

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import functools
import operator

try:
    from typing import TYPE_CHECKING
except ImportError:
    TYPE_CHECKING = False

if TYPE_CHECKING:
    from typing import Iterable, List, NamedTuple, Optional, Union
    from ansible.galaxy.collection.concrete_artifact_manager import (
        ConcreteArtifactsManager,
    )
    from ansible.galaxy.collection.galaxy_api_proxy import MultiGalaxyAPIProxy

from ansible.galaxy.dependency_resolution.dataclasses import (
    Candidate,
    Requirement,
)
from ansible.galaxy.dependency_resolution.versioning import (
    is_pre_release,
    meets_requirements,
)

from resolvelib import AbstractProvider


class CollectionDependencyProvider(AbstractProvider):
    """Delegate class providing requirement interface for the resolver.
    """

    def __init__(
            self,  # type: CollectionDependencyProvider
            apis,  # type: MultiGalaxyAPIProxy
            concrete_artifacts_manager=None,  # type: ConcreteArtifactsManager
            preferred_requirements=None,  # type: Iterable[Requirement]
            with_deps=True,  # type: bool
            with_pre_releases=False,  # type: bool
    ):  # type: (...) -> None
        r"""Initialize helper attributes.

        :param api: An instance of the multiple Galaxy APIs wrapper
        :type api: MultiGalaxyAPIProxy

        :param concrete_artifacts_manager: An instance of the caching \
                                           concrete artifacts manager
        :type concrete_artifacts_manager: ConcreteArtifactsManager

        :param with_deps: A flag specifying whether the resolver \
                                  should attempt to pull-in the \
                                  deps of the requested requirements. \
                                  On by default.
        :type with_deps: bool

        :param with_pre_releases: A flag specifying whether the \
                                  resolver should skip pre-releases. \
                                  Off by default.
        :type with_pre_releases: bool
        """
        self._api_proxy = apis
        self._make_req_from_dict = functools.partial(
            Requirement.from_requirement_dict,
            art_mgr=concrete_artifacts_manager,
        )
        self._preferred_requirements = set(preferred_requirements or ())
        self._with_deps = with_deps
        self._with_pre_releases = with_pre_releases

    def identify(self, requirement_or_candidate):
        # type: (Union[Candidate, Requirement]) -> str
        """Given a requirement or candidate, return an identifier for it.

        This is used to identify a requirement or candidate, e.g.
        whether two requirements should have their specifier parts
        merged, whether two candidates would conflict with each other
        (because they have same name but different versions).
        """
        # FIXME: what to do if it is None? Rely on src? Use the whole tuple?
        return requirement_or_candidate.canonical_package_id

    def get_preference(
            self,  # type: CollectionDependencyProvider
            resolution,  # type: Optional[Candidate]
            candidates,  # type: List[Candidate]
            information,  # type: List[NamedTuple]
    ):  # type: (...) -> Union[float, int]
        """Produce a sort key function return value for given requirement based on preference.

        FIXME: figure out the sort key
        The preference is defined as "I think this requirement should be
        resolved first". The lower the return value is, the more preferred
        this group of arguments is.
        :param resolution: Currently pinned candidate, or `None`.
        :param candidates: A list of possible candidates.
        :param information: A list of requirement information.
        Each information instance is a named tuple with two entries:
        * `requirement` specifies a requirement contributing to the current
          candidate list
        * `parent` specifies the candidate that provides (dependend on) the
          requirement, or `None` to indicate a root requirement.
        The preference could depend on a various of issues, including (not
        necessarily in this order):
        * Is this package pinned in the current resolution result?
        * How relaxed is the requirement? Stricter ones should probably be
          worked on first? (I don't know, actually.)
        * How many possibilities are there to satisfy this requirement? Those
          with few left should likely be worked on first, I guess?
        * Are there any known conflicts for this requirement? We should
          probably work on those with the most known conflicts.
        A sortable value should be returned (this will be used as the `key`
        parameter of the built-in sorting function). The smaller the value is,
        the more preferred this requirement is (i.e. the sorting function
        is called with `reverse=False`).
        """
        if any(
                candidate in self._preferred_requirements
                for candidate in candidates
        ):
            # NOTE: Prefer pre-installed candidates over newer versions
            # NOTE: available from Galaxy or other sources.
            return float('-inf')
        return len(candidates)

    def find_matches(self, requirements):
        # type: (List[Requirement]) -> List[Candidate]
        """Find all possible candidates that satisfy the given requirements.

        This should try to get candidates based on the requirements' types.
        For VCS, local, and archive requirements, the one-and-only match is
        returned, and for a "named" requirement, the index(es) should be
        consulted to find concrete candidates for this requirement.
        :param requirements: A collection of requirements which all of the
            returned candidates must match. All requirements are guaranteed to
            have the same identifier. The collection is never empty.
        :returns: An iterable that orders candidates by preference, e.g. the
            most preferred candidate should come first.
        """
        assert requirements, 'Broken contract of having non-empty requirements'

        # FIXME: The first requirement may be a Git repo followed by
        # FIXME: its cloned tmp dir. Using only the first one creates
        # FIXME: loops that prevent any further dependency exploration.
        # FIXME: We need to figure out how to prevent this.
        first_req = requirements[0]
        fqcn = first_req.fqcn
        # The fqcn is guaranteed to be the same
        coll_versions = self._api_proxy.get_collection_versions(first_req)
        if first_req.is_concrete_artifact:
            # FIXME: do we assume that all the following artifacts are also concrete?
            # FIXME: does using fqcn==None cause us problems here?

            return [
                Candidate(fqcn, version, _none_src_server, first_req.type)
                for version, _none_src_server in coll_versions
            ]

        preinstalled_candidates = {
            Candidate(req.fqcn, req.ver, req.src, req.type)
            for req in self._preferred_requirements
            if req.fqcn == fqcn
        }

        assert len(preinstalled_candidates) < 2, (
            'Max of 1 candidate is expected to be preinstalled'
        )

        candidates = {
            candidate for candidate in (
                Candidate(fqcn, version, src_server, 'galaxy')  # FIXME: type=galaxy?
                for version, src_server in coll_versions
            )
            for requirement in requirements
        }

        return list(preinstalled_candidates) + sorted(
            {
                candidate for candidate in candidates
                if all(self.is_satisfied_by(requirement, candidate) for requirement in requirements)
                # FIXME
                # if all(self.is_satisfied_by(requirement, candidate) and (
                #     requirement.src is None or
                #     requirement.src == candidate.src
                # ))
            },
            key=operator.attrgetter('ver', 'src'),
            reverse=True,  # prefer newer versions over older ones
        )

    def is_satisfied_by(self, requirement, candidate):
        # type: (Requirement, Candidate) -> bool
        """Whether the given requirement can be satisfied by a candidate.
        The candidate is guarenteed to have been generated from the
        requirement.
        A boolean should be returned to indicate whether `candidate` is a
        viable solution to the requirement.
        """
        # NOTE: Only allow pre-release candidates if we want pre-releases or
        # the req ver was an exact match with the pre-release version.
        allow_pre_release = self._with_pre_releases or not (
            requirement.ver == '*' or
            requirement.ver.startswith('<') or
            requirement.ver.startswith('>') or
            requirement.ver.startswith('!=')
        ) and not candidate.is_virtual

        if is_pre_release(candidate.ver) and not allow_pre_release:
            return False

        # NOTE: This is a set of Pipenv-inspired optimizations. Ref:
        # https://github.com/sarugaku/passa/blob/2ac00f1/src/passa/models/providers.py#L58-L74
        if (
                requirement.is_virtual or
                candidate.is_virtual or
                requirement.ver == '*'
        ):
            return True

        return meets_requirements(
            version=candidate.ver,
            requirements=requirement.ver,
        )

    def get_dependencies(self, candidate):
        # type: (Candidate) -> List[Candidate]
        r"""Get dependencies of a candidate.

        :returns: A collection of requirements that `candidate` \
                  specifies as its dependencies.
        :rtype: list[Candidate]
        """
        # FIXME: If there's several galaxy servers set, there may be a
        # FIXME: situation when the metadata of the same collection
        # FIXME: differs. So how do we resolve this case? Priority?
        # FIXME: Taking into account a pinned hash? Exploding on
        # FIXME: any differences?
        # NOTE: The underlying implmentation currently uses first found
        req_map = self._api_proxy.get_collection_dependencies(candidate)

        # NOTE: This guard expression MUST perform an early exit only
        # NOTE: after the `get_collection_dependencies()` call because
        # NOTE: internally it polulates the artifact URL of the candidate,
        # NOTE: its SHA hash and the Galaxy API token. These are still
        # NOTE: necessary with `--no-deps` because even with the disabled
        # NOTE: dependency resolution the outer layer will still need to
        # NOTE: know how to download and validate the artifact.
        #
        # NOTE: Virtual candidates should always return dependencies
        # NOTE: because they are ephemeral and non-installable.
        if not self._with_deps and not candidate.is_virtual:
            return []

        return [
            self._make_req_from_dict({'name': dep_name, 'version': dep_req})
            for dep_name, dep_req in req_map.items()
        ]
