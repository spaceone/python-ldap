"""
controls.py - support classes for LDAP controls

See https://www.python-ldap.org/ for details.

Description:
The ldap.controls module provides LDAPControl classes.
Each class provides support for a certain control.
"""

from __future__ import annotations

import inspect
from collections.abc import Sequence
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


def encode_request_ctrls(ctrls: Sequence[RequestControl] | None) -> tuple[str | None, bool, bytes | None] | None:
    """
    Return list of readily encoded 3-tuples which can be directly
    passed to C module ldap._ldap

    ctrls
        sequence-type of RequestControl objects
    """
    if ctrls is None:
        return None
    return [(c.controlType, c.criticality, c.encode()) for c in ctrls]


RequestControlTuples = encode_request_ctrls  # backwards compatibility


def decode_response_ctrls(
    ctrls: Sequence[tuple[str, bool, bytes]],
    ctrl_reg: dict[str, ResponseControl] | None = None,
):
    """
    Returns list of readily decoded ResponseControl objects

    ctrls
        Sequence-type of 3-tuples returned by ldap._ldap.result4() containing
        the encoded ASN.1 control values of response controls.
    ctrl_reg
        Dictionary mapping extended control's OID to ResponseControl class
        of response controls known by the application. If None
        ldap.controls.KNOWN_RESPONSE_CONTROLS is used here.
    """
    if ctrl_reg is None:
        ctrl_reg = KNOWN_RESPONSE_CONTROLS
    result = []
    for ctrl_type, ctrl_criticality, ctrl_val in ctrls or []:
        try:
            control_class = ctrl_reg.get(ctrl_type)
        except KeyError:
            if ctrl_criticality:
                raise ldap.UNAVAILABLE_CRITICAL_EXTENSION(f'Unknown critical response control, ctrl_type {ctrl_type!r}')
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


class ControlRegistry:
    """
    A simple registry for extended controls and their handler class
    """

    cmap: dict[str, ResponseControl]

    def __init__(self, *module_names):
        self.cmap = None
        self._module_names = module_names

    def _reg(self, *module_names):
        for module_name in module_names:
            module = import_module(module_name)
            for _, cls in inspect.getmembers(module, inspect.isclass):
                if issubclass(cls, ResponseControl) and hasattr(cls, 'controlType') and cls.controlType is not None:
                    self.cmap[cls.controlType] = cls

    def get(self, control_type):
        if self.cmap is None:
            self.cmap = {}
            self._reg(*self._module_names)
        return self.cmap[control_type]

    # TOOD: add backwards compat layer


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
