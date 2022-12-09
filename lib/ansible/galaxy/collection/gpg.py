# -*- coding: utf-8 -*-
# Copyright: (c) 2022, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Signature verification helpers."""

from ansible.errors import AnsibleError
from ansible.galaxy.user_agent import user_agent
from ansible.module_utils.urls import open_url

import contextlib
import os
import subprocess
import sys
import textwrap
import typing as t

from dataclasses import dataclass, fields as dc_fields, field
from functools import partial
from urllib.error import HTTPError, URLError

if t.TYPE_CHECKING:
    from ansible.utils.display import Display

IS_PY310_PLUS = sys.version_info[:2] >= (3, 10)

frozen_dataclass = partial(dataclass, frozen=True, **({'slots': True} if IS_PY310_PLUS else {}))


def get_signature_from_source(source, display=None):  # type: (str, t.Optional[Display]) -> str
    if display is not None:
        display.vvvv(f"Using signature at {source}")
    try:
        with open_url(
            source,
            http_agent=user_agent(),
            validate_certs=True,
            follow_redirects='safe'
        ) as resp:
            signature = resp.read()
    except (HTTPError, URLError) as e:
        raise AnsibleError(
            f"Failed to get signature for collection verification from '{source}': {e}"
        ) from e

    return signature


def run_gpg_verify(
    manifest_file,  # type: str
    signature,  # type: str
    keyring,  # type: str
    feedback,  # type: list[(str, str)]
):  # type: (...) -> tuple[str, int]
    status_fd_read, status_fd_write = os.pipe()

    # running the gpg command will create the keyring if it does not exist
    remove_keybox = not os.path.exists(keyring)

    cmd = [
        'gpg',
        f'--status-fd={status_fd_write}',
        '--verify',
        '--batch',
        '--no-tty',
        '--no-default-keyring',
        f'--keyring={keyring}',
        '-',
        manifest_file,
    ]
    cmd_str = ' '.join(cmd)
    feedback.append(("vvvv", f"Running command '{cmd}'"))

    try:
        p = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(status_fd_write,),
            encoding='utf8',
        )
    except (FileNotFoundError, subprocess.SubprocessError) as err:
        raise AnsibleError(
            f"Failed during GnuPG verification with command '{cmd_str}': {err}"
        ) from err
    else:
        stdout, stderr = p.communicate(input=signature)
    finally:
        os.close(status_fd_write)

    if remove_keybox:
        with contextlib.suppress(OSError):
            os.remove(keyring)

    with os.fdopen(status_fd_read) as f:
        stdout = f.read()
        feedback.append(("vvvv", f"stdout: \n{stdout}\nstderr: \n{stderr}\n(exit code {p.returncode})"))
        return stdout, p.returncode


def parse_gpg_errors(status_out):  # type: (str) -> t.Iterator[GpgBaseError]

    for line in status_out.splitlines():
        if not line:
            continue
        try:
            _dummy, status, remainder = line.split(maxsplit=2)
        except ValueError:
            _dummy, status = line.split(maxsplit=1)
            remainder = None

        try:
            cls = GPG_ERROR_MAP[status]
        except KeyError:
            continue

        fields = [status]
        if remainder:
            fields.extend(
                remainder.split(
                    None,
                    len(dc_fields(cls)) - 2
                )
            )

        yield cls(*fields)


@frozen_dataclass
class GpgBaseError(Exception):
    status: str

    @classmethod
    def get_gpg_error_description(cls) -> str:
        """Return the current class description."""
        return ' '.join(cls.__doc__.split())

    def __post_init__(self):
        for field in dc_fields(self):
            super(GpgBaseError, self).__setattr__(field.name, field.type(getattr(self, field.name)))


@frozen_dataclass
class GpgExpSig(GpgBaseError):
    """The signature with the keyid is good, but the signature is expired."""
    keyid: str
    username: str


@frozen_dataclass
class GpgExpKeySig(GpgBaseError):
    """The signature with the keyid is good, but the signature was made by an expired key."""
    keyid: str
    username: str


@frozen_dataclass
class GpgRevKeySig(GpgBaseError):
    """The signature with the keyid is good, but the signature was made by a revoked key."""
    keyid: str
    username: str


@frozen_dataclass
class GpgBadSig(GpgBaseError):
    """The signature with the keyid has not been verified okay."""
    keyid: str
    username: str


@frozen_dataclass
class GpgErrSig(GpgBaseError):
    """"It was not possible to check the signature.  This may be caused by
    a missing public key or an unsupported algorithm.  A RC of 4
    indicates unknown algorithm, a 9 indicates a missing public
    key.
    """
    keyid: str
    pkalgo: int
    hashalgo: int
    sig_class: str
    time: int
    rc: int
    fpr: str


@frozen_dataclass
class GpgNoPubkey(GpgBaseError):
    """The public key is not available."""
    keyid: str


@frozen_dataclass
class GpgMissingPassPhrase(GpgBaseError):
    """No passphrase was supplied."""


@frozen_dataclass
class GpgBadPassphrase(GpgBaseError):
    """The supplied passphrase was wrong or not given."""
    keyid: str


@frozen_dataclass
class GpgNoData(GpgBaseError):
    """No data has been found.  Codes for WHAT are:
    - 1 :: No armored data.
    - 2 :: Expected a packet but did not find one.
    - 3 :: Invalid packet found, this may indicate a non OpenPGP
           message.
    - 4 :: Signature expected but not found.
    """
    what: str


@frozen_dataclass
class GpgUnexpected(GpgBaseError):
    """No data has been found.  Codes for WHAT are:
    - 1 :: No armored data.
    - 2 :: Expected a packet but did not find one.
    - 3 :: Invalid packet found, this may indicate a non OpenPGP
           message.
    - 4 :: Signature expected but not found.
    """
    what: str


@frozen_dataclass
class GpgError(GpgBaseError):
    """This is a generic error status message, it might be followed by error location specific data."""
    location: str
    code: int
    more: str = ""


@frozen_dataclass
class GpgFailure(GpgBaseError):
    """This is the counterpart to SUCCESS and used to indicate a program failure."""
    location: str
    code: int


@frozen_dataclass
class GpgBadArmor(GpgBaseError):
    """The ASCII armor is corrupted."""


@frozen_dataclass
class GpgKeyExpired(GpgBaseError):
    """The key has expired."""
    timestamp: int


@frozen_dataclass
class GpgKeyRevoked(GpgBaseError):
    """The used key has been revoked by its owner."""


@frozen_dataclass
class GpgNoSecKey(GpgBaseError):
    """The secret key is not available."""
    keyid: str


GPG_ERROR_MAP = {
    'EXPSIG': GpgExpSig,
    'EXPKEYSIG': GpgExpKeySig,
    'REVKEYSIG': GpgRevKeySig,
    'BADSIG': GpgBadSig,
    'ERRSIG': GpgErrSig,
    'NO_PUBKEY': GpgNoPubkey,
    'MISSING_PASSPHRASE': GpgMissingPassPhrase,
    'BAD_PASSPHRASE': GpgBadPassphrase,
    'NODATA': GpgNoData,
    'UNEXPECTED': GpgUnexpected,
    'ERROR': GpgError,
    'FAILURE': GpgFailure,
    'BADARMOR': GpgBadArmor,
    'KEYEXPIRED': GpgKeyExpired,
    'KEYREVOKED': GpgKeyRevoked,
    'NO_SECKEY': GpgNoSecKey,
}


@dataclass
class SignatureResult:
    fqcn: str
    signature: str
    file: str
    keyring: str
    ignore_signature_errors: list[str]

    errors: list[GpgBaseError] = field(default_factory=list)
    feedback: list[(str, str)] = field(default_factory=list)

    _rc: int = 0
    _stdout: str = None
    _error_wrapper: textwrap.TextWrapper = None

    success: bool = False
    failed: bool = False
    ignored: bool = False

    def __post_init__(self):
        self._verify()

    def _report_unexpected(self):
        return (
            f"Unexpected error for '{self.fqcn}': "
            f"GnuPG signature verification failed with the return code {self._rc} and output {self._stdout}"
        )

    def _report_expected(self):
        header = f"Signature verification failed for '{self.fqcn}' (return code {self._rc}):"
        return header + self._format_errors()

    def _format_errors(self):
        if self._error_wrapper is None:
            self._error_wrapper = textwrap.TextWrapper(
                initial_indent="    * ",  # 6 chars
                subsequent_indent="      ",  # 6 chars
            )

        wrapped_reasons = [
            '\n'.join(self._error_wrapper.wrap(reason))
            for reason in self.errors
        ]

        return '\n' + '\n'.join(wrapped_reasons)

    def report(self):
        if not self.failed:
            return

        if self.errors:
            return self._report_expected()

        return self._report_unexpected()

    def _verify(self):
        self._stdout, self._rc = run_gpg_verify(self.file, self.signature, self.keyring, self.feedback)

        any_ignored = False
        for error in parse_gpg_errors(self._stdout):
            status_code = list(GPG_ERROR_MAP.keys())[list(GPG_ERROR_MAP.values()).index(error.__class__)]
            if status_code in self.ignore_signature_errors:
                any_ignored = True
                continue
            self.errors.append(error.get_gpg_error_description())

        if self.errors or (not any_ignored and self._rc != 0):
            self.failed = True
        elif any_ignored:
            self.ignored = True
        else:
            self.success = True

        if (report := self.report()) is not None:
            self.feedback.append(('vvvv', report))

@dataclass
class SignatureResults:
    strict: bool
    required_all: bool
    required_count: int
    signatures: list[str]
    ignore_signature_errors: list[str]
    keyring: str
    manifest_file: str

    signature_results: list[SignatureResult] = field(default_factory=list)
    feedback: list[(str, str)] = field(default_factory=list)
    success: bool = False

    def __post_init__(self):
        self._verify_signatures()
        self._verify()

    @property
    def _fqcn(self):
        coll_path_parts = self.manifest_file.split(os.path.sep)
        return '%s.%s' % (coll_path_parts[-3], coll_path_parts[-2])  # get 'ns' and 'coll' from /path/to/ns/coll/MANIFEST.json

    def _verify_signatures(self):
        self.signature_results.extend(
            # VerifyResult(signature, self.manifest_file, self.keyring, self.ignore_signature_errors)
            SignatureResult(self._fqcn, signature, self.manifest_file, self.keyring, self.ignore_signature_errors)
            for signature in self.signatures
        )

    def _verify(self):
        successful_results = [result for result in self.signature_results if result.success]
        failed_results = [result for result in self.signature_results if result.failed]

        failed_strict = self.strict and len(successful_results) == 0
        failed_all = bool(self.required_all and failed_results)
        failed_req = not self.required_all and self.signatures and self.required_count > len(successful_results)

        if failed_strict or failed_all or failed_req:
            for result in failed_results:
                self.feedback.extend(result.feedback)
            if failed_strict:
                self.feedback.append(("display", f"Signature verification failed for '{self._fqcn}': no successful signatures"))
            elif failed_all:
                self.feedback.append(("display", f"Signature verification failed for '{self._fqcn}': some signatures failed"))
            elif failed_req:
                self.feedback.append(("display", f"Required {self.required_count} and only had {len(successful_results)} - {successful_results}"))
                self.feedback.append(("display", f"Signature verification failed for '{self._fqcn}': fewer successful signatures than required"))
        else:
            self.success = True
