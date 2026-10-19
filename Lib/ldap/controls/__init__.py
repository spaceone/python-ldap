"""
controls.py - support classes for LDAP controls

See https://www.python-ldap.org/ for details.

Description:
The ldap.controls module provides LDAPControl classes.
Each class provides support for a certain control.
"""

from __future__ import annotations

import inspect
import warnings
from collections.abc import Iterator, Mapping, MutableMapping, Sequence
from importlib import import_module

from pyasn1.error import PyAsn1Error

import ldap


__all__ = [
    'KNOWN_RESPONSE_CONTROLS',
    # Classes
    'AssertionControl',
    'BooleanControl',
    'DecodeControlTuples',
    'LDAPControl',
    'ManageDSAITControl',
    'MatchedValuesControl',
    'RelaxRulesControl',
    'RequestControl',
    # Functions
    'RequestControlTuples',
    'ResponseControl',
    'SimplePagedResultsControl',
    'ValueLessRequestControl',
]


class RequestControl:
    """
    Base class for all request controls

    controlType
        OID as string of the LDAPv3 extended request control
    criticality
        sets the criticality of the control (boolean)
    encodedControlValue
        control value of the LDAPv3 extended request control
        (here it is the BER-encoded ASN.1 control value)
    """

    controlType: str | None = None

    def __init__(
        self, controlType: str | None = None, criticality: bool = False, encodedControlValue: bytes | None = None
    ) -> None:
        if controlType is not None:
            self.controlType = controlType
        self.criticality = criticality
        self.encodedControlValue = encodedControlValue

    def encode(self) -> bytes | None:
        """
        sets class attribute encodedControlValue to the BER-encoded ASN.1
        control value composed by class attributes set before
        """
        if type(self).encodeControlValue is not RequestControl.encodeControlValue:
            warnings.warn(
                'encodeControlValue() has been renamed into encode() - will be removed in 4.0',
                DeprecationWarning,
                stacklevel=2,
            )
        return self.encodeControlValue()

    def encodeControlValue(self) -> bytes | None:
        return self.encodedControlValue


class ResponseControl:
    """
    Base class for all response controls

    controlType
        OID as string of the LDAPv3 extended response control
    criticality
        sets the criticality of the received control (boolean)
    """

    def __init_subclass__(cls, *, register: bool = True, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)

        control_type = cls.__dict__.get('controlType')  # prevent inherited classes to be registered
        if register and control_type:
            KNOWN_RESPONSE_CONTROLS.setdefault(control_type, cls)

    def __init__(self, controlType: str | None = None, criticality: bool = False) -> None:
        self.controlType = controlType
        self.criticality = criticality

    def decode(self, value: bytes) -> None:
        """
        decodes the BER-encoded ASN.1 control value and sets the appropriate
        class attributes
        """
        return self.decodeControlValue(value)

    def decodeControlValue(self, encodedControlValue: bytes) -> None:
        # The type hint can be removed once class LDAPControl is removed
        self.encodedControlValue: bytes | None = encodedControlValue
        warnings.warn(
            'decodeControlValue() has been renamed into decode() - will be removed in 4.0',
            DeprecationWarning,
            stacklevel=2,
        )


class LDAPControl(RequestControl, ResponseControl):
    """
    Base class for combined request/response controls mainly
    for backward-compatibility to python-ldap 2.3.x
    """

    def __init__(
        self,
        controlType: str | None = None,
        criticality: bool = False,
        controlValue: str | None = None,
        value: bytes | None = None,
    ) -> None:
        self.controlType = controlType
        self.criticality = criticality
        self.controlValue = controlValue
        self.value = value


def encode_request_ctrls(
    ctrls: Sequence[RequestControl] | None,
) -> list[tuple[str | None, bool, bytes | None]] | None:
    """
    Convert request controls into tuples suitable for the LDAP C extension.

    :param ctrls:
        Sequence of :class:`RequestControl` objects.
        If :const:`None`, no controls are encoded.
    :return:
        List of 3-tuples containing the control OID, criticality,
        and BER-encoded control value, or :const:`None` if
        `ctrls` is :const:`None`.
    """
    if ctrls is None:
        return None
    return [(c.controlType, c.criticality, c.encode()) for c in ctrls]


RequestControlTuples = encode_request_ctrls  # backwards compatibility


def decode_response_ctrls(
    ctrls: Sequence[tuple[str, bool, bytes]] | None,
    ctrl_reg: Mapping[str, type[ResponseControl]] | None = None,
) -> list[ResponseControl]:
    """
    Decode LDAP response control tuples into ResponseControl objects.

    :param ctrls:
        Sequence of 3-tuples returned by :meth:`ldap.ldapobject.LDAPObject.result4`,
        containing the encoded ASN.1 values of response controls.
    :param ctrl_reg:
        Dictionary mapping response control OIDs to
        :class:`ResponseControl` subclasses.
        If :const:`None`, the global :data:`KNOWN_RESPONSE_CONTROLS`
        registry is used.
    :return:
        List of decoded :class:`ResponseControl` objects.
    """
    if ctrl_reg is None:
        ctrl_reg = KNOWN_RESPONSE_CONTROLS
    result = []
    for ctrl_type, ctrl_criticality, ctrl_val in ctrls or []:
        try:
            control_class = ctrl_reg[ctrl_type]
        except KeyError:
            if ctrl_criticality:
                raise ldap.UNAVAILABLE_CRITICAL_EXTENSION(
                    f'Unknown critical response control for controlType={ctrl_type!r}'
                )
        else:
            control = control_class(criticality=ctrl_criticality)
            try:
                control.decode(ctrl_val)
            except PyAsn1Error:
                if ctrl_criticality:
                    raise
            else:
                result.append(control)
    return result


DecodeControlTuples = decode_response_ctrls  # backwards compatibility


class ControlRegistry(MutableMapping[str, type[ResponseControl]]):
    """
    Lazily loaded registry mapping response control OIDs to classes.
    """

    def __init__(self, *module_names: str) -> None:
        self._cmap: dict[str, type[ResponseControl]] = {}
        self._module_names = module_names
        self._loaded = False

    def _load(self) -> None:
        if self._loaded:
            return

        self._loaded = True

        for module_name in self._module_names:
            module = import_module(module_name)

            for _, cls in inspect.getmembers(module, inspect.isclass):
                if issubclass(cls, ResponseControl) and cls is not ResponseControl:
                    control_type = getattr(cls, 'controlType', None)
                    if control_type is not None:
                        self._cmap.setdefault(control_type, cls)

    def __getitem__(self, key: str) -> type[ResponseControl]:
        self._load()
        return self._cmap[key]

    def __setitem__(self, key: str, value: type[ResponseControl]) -> None:
        self._load()
        self._cmap[key] = value

    def __delitem__(self, key: str) -> None:
        self._load()
        del self._cmap[key]

    def __iter__(self) -> Iterator[str]:
        self._load()
        return iter(self._cmap)

    def __len__(self) -> int:
        self._load()
        return len(self._cmap)


# response control OID to class registry
KNOWN_RESPONSE_CONTROLS = ControlRegistry(
    __name__ + '.deref',
    __name__ + '.libldap',
    __name__ + '.openldap',
    __name__ + '.pagedresults',
    __name__ + '.ppolicy',
    __name__ + '.psearch',
    __name__ + '.pwdpolicy',
    __name__ + '.readentry',
    __name__ + '.sessiontrack',
    __name__ + '.simple',
    __name__ + '.sss',
    __name__ + '.syncrepl',
    __name__ + '.vlv',
)


from ldap.controls.libldap import *  # noqa: E402
from ldap.controls.simple import *  # noqa: E402
