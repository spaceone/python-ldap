"""
ldap.schema.subentry -  subschema subentry handling

See https://www.python-ldap.org/ for details.
"""

from __future__ import annotations
from itertools import combinations

from ..cidict import CIDict
from ..dn import DNObj
from .models import (
    AttributeType,
    DITContentRule,
    DITStructureRule,
    LDAPSyntax,
    MatchingRule,
    MatchingRuleUse,
    NameForm,
    ObjectClass,
    SchemaElementOIDSet,
)


__all__ = [
    'SCHEMA_ATTR_MAPPING',
    'SCHEMA_CLASS_MAPPING',
    'NameNotUnique',
    'OIDNotUnique',
    'SubSchema',
    'SubschemaError',
]

SCHEMA_ATTR_MAPPING = {
    AttributeType: AttributeType.schema_attribute,
    DITContentRule: DITContentRule.schema_attribute,
    DITStructureRule: DITStructureRule.schema_attribute,
    LDAPSyntax: LDAPSyntax.schema_attribute,
    MatchingRule: MatchingRule.schema_attribute,
    MatchingRuleUse: MatchingRuleUse.schema_attribute,
    NameForm: NameForm.schema_attribute,
    ObjectClass: ObjectClass.schema_attribute,
}
SCHEMA_CLASS_MAPPING = CIDict(
    {
        AttributeType.schema_attribute: AttributeType,
        DITContentRule.schema_attribute: DITContentRule,
        DITStructureRule.schema_attribute: DITStructureRule,
        LDAPSyntax.schema_attribute: LDAPSyntax,
        MatchingRule.schema_attribute: MatchingRule,
        MatchingRuleUse.schema_attribute: MatchingRuleUse,
        NameForm.schema_attribute: NameForm,
        ObjectClass.schema_attribute: ObjectClass,
    }
)
SCHEMA_ATTRS = list(SCHEMA_CLASS_MAPPING.keys())


class SubschemaError(ValueError):
    pass


class OIDNotUnique(SubschemaError):
    def __init__(self, desc: str) -> None:
        self.desc = desc

    def __str__(self) -> str:
        return f'OID not unique for {self.desc}'


class NameNotUnique(SubschemaError):
    def __init__(self, desc: str) -> None:
        self.desc = desc

    def __str__(self) -> str:
        return f'NAME not unique for {self.desc}'


class SubSchema:
    """
    Arguments:

    sub_schema_sub_entry
        Dictionary usually returned by LDAP search or the LDIF parser
        containing the sub schema sub entry

    check_uniqueness
        Defines whether uniqueness of OIDs and NAME is checked.

        0
          no check
        1
          check but add schema description with work-around
        2
          check and raise exception if non-unique OID or NAME is found

    Class attributes:

    sed
      Dictionary holding the subschema information as pre-parsed
      SchemaElement objects (do not access directly!)
    name2oid
      Dictionary holding the mapping from NAMEs to OIDs
      (do not access directly!)
    non_unique_oids
      List of OIDs used at least twice in the subschema
    non_unique_names
      List of NAMEs used at least twice in the subschema for the same schema element
    """

    def __init__(
        self,
        sub_schema_sub_entry,
        subentry_dn=None,
        check_uniqueness=True,
    ):

        # Initialize all dictionaries
        self.name2oid = {}
        self.sed = {}
        self.non_unique_oids = {}
        self.non_unique_names = {}
        for c in SCHEMA_CLASS_MAPPING.values():
            self.name2oid[c] = CIDict(keytype=str)
            self.sed[c] = {}
            self.non_unique_names[c] = CIDict(keytype=str)

        # Transform entry dict to case-insensitive dict
        e = CIDict(sub_schema_sub_entry, keytype=str)

        # Build the schema registry in dictionaries
        for attr_type in SCHEMA_ATTRS:
            for attr_value in filter(None, e.get(attr_type, [])):
                se_class = SCHEMA_CLASS_MAPPING[attr_type]
                se_instance = se_class(attr_value)
                se_id = se_instance.get_id()

                if check_uniqueness and se_id in self.sed[se_class]:
                    self.non_unique_oids[se_id] = None
                    if check_uniqueness == 1:
                        # Add to subschema by adding suffix to ID
                        suffix_counter = 1
                        new_se_id = se_id
                        while new_se_id in self.sed[se_class]:
                            new_se_id = ';'.join((se_id, str(suffix_counter)))
                            suffix_counter += 1
                        se_id = new_se_id
                    elif check_uniqueness >= 2:
                        raise OIDNotUnique(attr_value)

                # Store the schema element instance in the central registry
                self.sed[se_class][se_id] = se_instance

                if hasattr(se_instance, 'names'):
                    for name in CIDict({}.fromkeys(se_instance.names)):
                        if check_uniqueness and name in self.name2oid[se_class]:
                            self.non_unique_names[se_class][se_id] = None
                            raise NameNotUnique(attr_value)
                        self.name2oid[se_class][name] = se_id

        # Turn dict into list maybe more handy for applications
        self.non_unique_oids = self.non_unique_oids.keys()
        self.subentry_dn = subentry_dn
        self.no_user_mod_attr_oids = self.determine_no_user_mod_attrs()
        # end of SubSchema()

    def ldap_entry(self) -> dict[str, list[str]]:
        """
        Returns a dictionary containing the sub schema sub entry

        The keys of the dict are the schema element attribute name and
        the values are lists of schema element definition strings.
        """
        # Initialize the dictionary with empty lists
        entry: dict[str, list[str]] = {}
        # Collect the schema elements and store them in
        # entry's attributes
        for se_class, elements in self.sed.items():
            for se in elements.values():
                se_str = str(se)
                try:
                    entry[SCHEMA_ATTR_MAPPING[se_class]].append(se_str)
                except KeyError:
                    entry[SCHEMA_ATTR_MAPPING[se_class]] = [se_str]
        return entry

    def listall(
        self,
        schema_element_class: type[SchemaElement],
        schema_element_filters: Iterable[tuple[str, Iterable[str | int]]] | None = None,
    ) -> list[str]:
        """
        Returns a list of OIDs of all available schema
        elements of a given schema element class.

        Arguments:

        schema_element_class
            The schema element class to limit the search to

        schema_element_filters
            A list of 2-tuples containing an attribute name and a sequence
            of possible values for the attribute name. If any filter matches,
            the element will be included in the returned list.
        """
        avail_se = self.sed[schema_element_class]
        if schema_element_filters:
            result = []
            for se_key, se in avail_se.items():
                for fk, fv in schema_element_filters:
                    try:
                        if getattr(se, fk) in fv:
                            result.append(se_key)
                            # FIXME: should break here?
                    except AttributeError:
                        pass
        else:
            result = list(avail_se)
        return result

    def tree(
        self,
        schema_element_class: type[ObjectClass | AttributeType],
        schema_element_filters: Iterable[tuple[str, Iterable[str | int]]] | None = None,
    ) -> CIDict[list[str]]:
        """
        Returns a ldap.CIDict.CIDict dictionary representing the
        tree structure of the schema elements.

        The dict will have the key '_' as the root element, and each
        key maps to a list of OIDs (inferior or child attributes), which
        can in turn be used as keys to work down the hierarchy.

        Arguments:

        schema_element_class
            The schema element class to limit the search to
            Note that only ``ObjectClass`` and ``AttributeType`` are supported.

        schema_element_filters
            A list of 2-tuples containing an attribute name and a sequence
            of possible values for the attribute name. If any filter matches,
            the element will be included in the returned dict.
        """
        assert schema_element_class in [ObjectClass, AttributeType]
        avail_se = self.listall(schema_element_class, schema_element_filters)
        top_node = '_'
        tree: CIDict[list[str]] = CIDict({top_node: []})
        # 1. Pass: Register all nodes
        for se in avail_se:
            tree[se] = []
        # 2. Pass: Register all sup references
        for se_oid in avail_se:
            se_obj = self.get_obj(schema_element_class, se_oid, None)
            if se_obj.__class__ != schema_element_class:
                # Ignore schema elements not matching schema_element_class.
                # This helps with falsely assigned OIDs.
                continue
            # FIXME: This assertion is superfluous?
            assert se_obj.__class__ == schema_element_class, (
                f'Schema element referenced by {se_oid} must be of class {schema_element_class.__name__} but was {se_obj.__class__}'
            )
            for s in se_obj.sup or ('_',):
                sup_oid = self.get_oid(schema_element_class, s)
                try:
                    tree[sup_oid].append(se_oid)
                except KeyError:
                    continue
        return tree

    def get_oid(self, se_class, nameoroid, raise_keyerror=0):
        """
        Get an OID by name or OID
        """
        nameoroid_stripped = nameoroid.split(';', maxsplit=1)[0].strip()
        if nameoroid_stripped in self.sed[se_class]:
            # name_or_oid is already a registered OID
            return nameoroid_stripped
        try:
            # try to look up OID by name
            result_oid = self.name2oid[se_class][nameoroid_stripped]
        except KeyError:
            if raise_keyerror:
                # raise error so zhe caller has to deal with it
                raise KeyError(f'No registered {se_class.__name__}-OID for nameoroid {nameoroid_stripped!r}')
            # just return the name
            result_oid = nameoroid_stripped
        return result_oid
        # end of get_oid()

    def get_inheritedattr(
        self,
        se_class: type[SchemaElementSubclass],
        nameoroid: str,
        name: str,
    ) -> Any:
        """
        Get a possibly inherited attribute specified by name
        of a schema element specified by nameoroid.
        Returns None if class attribute is not set at all.

        Raises KeyError if no schema element is found by nameoroid.
        """
        se = self.sed[se_class][self.get_oid(se_class, nameoroid)]
        try:
            result = getattr(se, name)
        except AttributeError:
            result = None
        if result is None and se.sup:
            result = self.get_inheritedattr(se_class, se.sup[0], name)
        return result

    def get_obj(
        self,
        se_class: type[SchemaElementSubclass],
        nameoroid: str,
        default: SchemaElementSubclass | None = None,
        raise_keyerror: int = 0,
    ) -> SchemaElementSubclass | None:
        """
        Get a schema element by name or OID
        """
        se_oid = self.get_oid(se_class, nameoroid)
        try:
            se_obj = self.sed[se_class][se_oid]
        except KeyError:
            if raise_keyerror:
                raise KeyError(
                    f'No ldap.schema.{se_class.__name__} instance with nameoroid {nameoroid!r} and se_oid {se_oid!r}'
                )
            se_obj = default
        return se_obj

    def get_inheritedobj(
        self,
        se_class: type[SchemaElementSubclass],
        nameoroid: str,
        inherited: list[str] | None = None,
    ) -> SchemaElementSubclass | None:
        """
        Get a schema element by name or OID with all class attributes
        set including inherited class attributes
        """
        import copy

        inherited = inherited or []
        se = copy.copy(self.sed[se_class].get(self.get_oid(se_class, nameoroid)))
        if se and hasattr(se, 'sup'):
            for class_attr_name in inherited:
                setattr(se, class_attr_name, self.get_inheritedattr(se_class, nameoroid, class_attr_name))

        return se

    def get_syntax(self, nameoroid: str) -> str | None:
        """
        Get the syntax of an attribute type specified by name or OID
        """
        try:
            syntax = self.get_inheritedattr(AttributeType, nameoroid, 'syntax')
        except KeyError:
            return None
        return syntax

    def get_structural_oc(self, oc_list: Iterable[str]) -> str | None:
        """
        Returns OID of structural object class in oc_list
        if any is present. Returns None else.
        """
        # Get tree of all STRUCTURAL object classes
        oc_tree = self.tree(ObjectClass, [('kind', {0})])
        # Filter all STRUCTURAL object classes
        struct_ocs = {}
        for oc_nameoroid in oc_list:
            oc_se = self.get_obj(ObjectClass, oc_nameoroid, None)
            if oc_se and oc_se.kind == 0:
                struct_ocs[oc_se.oid] = None
        result = None
        struct_oc_list = list(struct_ocs.keys())
        while struct_oc_list:
            oid = struct_oc_list.pop()
            for child_oid in oc_tree[oid]:
                if self.get_oid(ObjectClass, child_oid) in struct_ocs:
                    break
            else:
                result = oid
        return result

    def get_applicable_aux_classes(self, nameoroid: str) -> list[str]:
        """
        Return a list of the applicable AUXILIARY object classes
        for a STRUCTURAL object class specified by 'nameoroid'
        if the object class is governed by a DIT content rule.
        If there's no DIT content rule all available AUXILIARY
        object classes are returned.
        """
        content_rule = self.get_obj(DITContentRule, nameoroid)
        if content_rule:
            # Return AUXILIARY object classes from DITContentRule instance
            return content_rule.aux
        # list all AUXILIARY object classes
        return self.listall(ObjectClass, [('kind', [2])])

    def attribute_types(  # noqa: C901
        self,
        object_class_list: Iterable[str],
        attr_type_filter: Iterable[tuple[str, Iterable[str | int]]] | None = None,
        raise_keyerror: int = 1,
        ignore_dit_content_rule: int = 0,
    ) -> tuple[CIDict[AttributeType | None], CIDict[AttributeType | None]]:
        """
        Returns a 2-tuple of all must and may attributes including
        all inherited attributes of superior object classes
        by walking up classes along the SUP attribute.

        The attributes are stored in ldap.CIDict.CIDict dictionaries.

        object_class_list
            list of strings specifying object class names or OIDs
        attr_type_filter
            list of 2-tuples containing a class attribute name and a
            list of class attributes which has to be matched
        raise_keyerror
            All KeyError exceptions for non-existent schema elements
            are ignored
        ignore_dit_content_rule
            A DIT content rule governing the structural object class
            is ignored
        """

        # Map object_class_list to object_class_oids (list of OIDs)
        object_class_oids = [self.get_oid(ObjectClass, o) for o in object_class_list]
        # Initialize
        oid_cache = {}

        r_must, r_may = CIDict(), CIDict()
        if '1.3.6.1.4.1.1466.101.120.111' in object_class_oids:
            # Object class 'extensibleObject' MAY carry every attribute type
            for at_obj in self.sed[AttributeType].values():
                r_may[at_obj.oid] = at_obj

        # Loop over OIDs of all given object classes
        while object_class_oids:
            object_class_oid = object_class_oids.pop(0)
            # Check whether the objectClass with this OID
            # has already been processed
            if object_class_oid in oid_cache:
                continue
            # Cache this OID as already being processed
            oid_cache[object_class_oid] = None
            try:
                object_class = self.sed[ObjectClass][object_class_oid]
            except KeyError:
                if raise_keyerror:
                    raise
                # Ignore this object class
                continue
            assert isinstance(object_class, ObjectClass)
            assert hasattr(object_class, 'must'), ValueError(object_class_oid)
            assert hasattr(object_class, 'may'), ValueError(object_class_oid)
            for a in object_class.must:
                se_oid = self.get_oid(AttributeType, a, raise_keyerror=raise_keyerror)
                r_must[se_oid] = self.get_obj(AttributeType, se_oid, raise_keyerror=raise_keyerror)
            for a in object_class.may:
                se_oid = self.get_oid(AttributeType, a, raise_keyerror=raise_keyerror)
                r_may[se_oid] = self.get_obj(AttributeType, se_oid, raise_keyerror=raise_keyerror)

            object_class_oids.extend([self.get_oid(ObjectClass, o) for o in object_class.sup])

        # Process DIT content rules
        if not ignore_dit_content_rule:
            structural_oc = self.get_structural_oc(object_class_list)
            if structural_oc:
                # Process applicable DIT content rule
                try:
                    dit_content_rule = self.get_obj(DITContentRule, structural_oc, raise_keyerror=1)
                except KeyError:
                    # No DIT content rule found for structural objectclass
                    pass
                else:
                    for a in dit_content_rule.must:
                        se_oid = self.get_oid(AttributeType, a, raise_keyerror=raise_keyerror)
                        r_must[se_oid] = self.get_obj(AttributeType, se_oid, raise_keyerror=raise_keyerror)
                    for a in dit_content_rule.may:
                        se_oid = self.get_oid(AttributeType, a, raise_keyerror=raise_keyerror)
                        r_may[se_oid] = self.get_obj(AttributeType, se_oid, raise_keyerror=raise_keyerror)
                    for a in dit_content_rule.nots:
                        a_oid = self.get_oid(AttributeType, a, raise_keyerror=raise_keyerror)
                        try:
                            del r_may[a_oid]
                        except KeyError:
                            pass

        # Remove all mandantory attribute types from
        # optional attribute type list
        for a in list(r_may):
            if a in r_must:
                del r_may[a]

        # Apply attr_type_filter to results
        if attr_type_filter:
            for l in [r_must, r_may]:
                for a in list(l):
                    for afk, afv in attr_type_filter:
                        try:
                            schema_attr_type = self.sed[AttributeType][a]
                        except KeyError:
                            if raise_keyerror:
                                raise KeyError(f'No attribute type found in sub schema by name {a}')
                            # If there's no schema element for this attribute type
                            # but still KeyError is to be ignored we filter it away
                            del l[a]
                            break
                        else:
                            if getattr(schema_attr_type, afk) not in afv:
                                del l[a]
                                break

        return r_must, r_may

    def get_all_operational_attributes(self, only_user_editable=False):
        """
        Returns SchemaElementOIDSet with all operational attributes
        """
        res = SchemaElementOIDSet(self, AttributeType, [])
        for at_obj in self.sed[AttributeType].values():
            if at_obj.usage != 0 and (not only_user_editable or not (at_obj.no_user_mod or at_obj.collective)):
                res.add(at_obj.oid)
        return res

    def determine_no_user_mod_attrs(self):
        result = {}.fromkeys([a.oid for a in self.sed[AttributeType].values() if a.no_user_mod])
        return result

    def get_associated_name_forms(self, structural_object_class_oid):
        """
        Returns a list of instances of NameForm
        representing all name forms associated with the current structural
        object class of this entry.

        The structural object class is determined by attribute
        'structuralObjectClass' if it exists or by calling
        method get_structural_oc() if not.
        """
        if structural_object_class_oid is None:
            return []
        structural_object_class_obj = self.get_obj(ObjectClass, structural_object_class_oid)
        if structural_object_class_obj:
            structural_object_class_names = [oc_name.lower() for oc_name in structural_object_class_obj.names or ()]
        else:
            structural_object_class_names = ()
        result = []
        for name_form_obj in self.sed[NameForm].values():
            if not name_form_obj.obsolete and (
                name_form_obj.oc == structural_object_class_oid
                or name_form_obj.oc.lower() in structural_object_class_names
            ):
                result.append(name_form_obj)
        return result

    def get_rdn_variants(self, structural_object_class_oid):
        rdn_variants = []
        for name_form_obj in self.get_associated_name_forms(structural_object_class_oid):
            rdn_variants.append((name_form_obj, name_form_obj.must))
            for l in range(1, len(name_form_obj.may)):
                for i in combinations(name_form_obj.may, l):
                    rdn_variants.append((name_form_obj, name_form_obj.must + i))
        return rdn_variants

    def get_rdn_templates(self, structural_object_class_oid):
        """
        convert the tuple RDN combinations to RDN template strings
        """
        rdn_attr_tuples = {}.fromkeys(
            [rdn_attr_tuple for name_form_obj, rdn_attr_tuple in self.get_rdn_variants(structural_object_class_oid)]
        ).keys()
        return ['+'.join([f'{attr_type}=' for attr_type in attr_types]) for attr_types in rdn_attr_tuples]

    def get_applicable_name_form_objs(self, dn, structural_object_class_oid):
        """
        Returns a list of instances of NameForm
        representing all name form associated with the current structural
        object class of this entry and matching the current RDN.
        """
        if dn:
            rdn_list = DNObj.from_str(dn)[0]
            current_rdn_attrs = [attr_type.lower() for attr_type, _ in rdn_list]
            current_rdn_attrs.sort()
        else:
            current_rdn_attrs = []
        result = []
        for name_form_obj, rdn_attr_tuple in self.get_rdn_variants(structural_object_class_oid):
            name_form_rdn_attrs = [attr_type.lower() for attr_type in rdn_attr_tuple]
            name_form_rdn_attrs.sort()
            if current_rdn_attrs == name_form_rdn_attrs:
                result.append(name_form_obj)
        return result

    def get_possible_dit_structure_rules(self, dn, structural_object_class_oid):
        name_form_identifiers = CIDict()
        for name_form_obj in self.get_applicable_name_form_objs(dn, structural_object_class_oid):
            name_form_identifiers[name_form_obj.oid] = None
        dit_struct_ruleids = {}
        for dit_struct_rule_obj in self.sed[DITStructureRule].values():
            name_form_obj = self.get_obj(NameForm, dit_struct_rule_obj.form)
            if (
                name_form_obj is not None
                and (name_form_obj.oid in name_form_identifiers)
                and (self.get_oid(ObjectClass, name_form_obj.oc) == structural_object_class_oid)
            ):
                dit_struct_ruleids[dit_struct_rule_obj.ruleid] = dit_struct_rule_obj
        return dit_struct_ruleids.keys()

    def get_subord_structural_oc_names(self, ruleid):
        subord_structural_oc_oids = {}
        subord_structural_ruleids = {}
        for dit_struct_rule_obj in self.sed[DITStructureRule].values():
            for sup in dit_struct_rule_obj.sup:
                if sup == ruleid:
                    subord_structural_ruleids[dit_struct_rule_obj.ruleid] = None
                    name_form_obj = self.get_obj(
                        NameForm,
                        dit_struct_rule_obj.form,
                    )
                    if name_form_obj:
                        name_form_oid = self.get_oid(ObjectClass, name_form_obj.oc)
                        subord_structural_oc_oids[name_form_oid] = None
        result = []
        for oc_oid in subord_structural_oc_oids:
            oc_obj = self.get_obj(ObjectClass, oc_oid)
            if oc_obj and oc_obj.names:
                result.append(oc_obj.names[0])
            else:
                result.append(oc_oid)
        return subord_structural_ruleids.keys(), result

    def get_superior_structural_oc_names(self, ruleid):
        try:
            dit_struct_rule_obj = self.sed[DITStructureRule][ruleid]
        except KeyError:
            return None
        else:
            result = []
            sup_ruleids = []
            for sup_ruleid in dit_struct_rule_obj.sup:
                try:
                    sup_dit_struct_rule_obj = self.sed[DITStructureRule][sup_ruleid]
                except KeyError:
                    pass
                else:
                    if sup_dit_struct_rule_obj.form:
                        sup_name_form_obj = self.get_obj(
                            NameForm,
                            sup_dit_struct_rule_obj.form,
                        )
                        if sup_name_form_obj:
                            sup_ruleids.append(sup_ruleid)
                            result.append(sup_name_form_obj.oc)
        return sup_ruleids, result
