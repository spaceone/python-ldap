# -*- coding: ascii -*-
"""
ldap0.schema.parse - Low-level parsing functions for schema element strings
"""

import re


UNESCAPE_PATTERN = re.compile(r'\\(.)')


TOKENS_FINDALL = re.compile(
    r'(\()'  # opening parenthesis
    r'|'  # or
    r'(\))'  # closing parenthesis
    r'|'  # or
    r"([^'$()\s]+)"  # string of length >= 1 without '$() or whitespace
    r'|'  # or
    # any string or empty string surrounded by unescaped single quotes
    # except if right quote is succeeded by alphanumeric char
    r"('(?:[^'\\]|\\.)*'(?!\w))"
    r'|'  # or
    r'([^\s]+?)',  # residue, all non-whitespace strings
).findall


def split_tokens(sch_str):
    """
    Returns list of syntax elements with quotes and spaces stripped.
    """
    parts = []
    parens = 0
    for opar, cpar, unquoted, quoted, residue in TOKENS_FINDALL(sch_str):
        if unquoted:
            parts.append(unquoted)
        elif quoted:
            parts.append(UNESCAPE_PATTERN.sub(r'\1', quoted[1:-1]))
        elif opar:
            parens += 1
            parts.append(opar)
        elif cpar:
            parens -= 1
            parts.append(cpar)
        elif residue == '$':
            if not parens:
                raise ValueError(f"'$' outside parenthesis in {sch_str!r}")
        else:
            raise ValueError(residue, sch_str)
    if parens:
        raise ValueError(f'Unbalanced parenthesis in {sch_str!r}')
    return parts


def extract_tokens(tkl, known_tokens):
    """
    Returns dictionary of known tokens with all values
    """
    assert tkl[0].strip() == '(' and tkl[-1].strip() == ')', ValueError(tkl)
    result = dict(known_tokens)
    i = 0
    l_len = len(tkl)
    while i < l_len:
        if tkl[i] in result:
            token = tkl[i]
            i += 1  # Consume token
            if i < l_len:
                if tkl[i] in result or tkl[i] == ')':
                    # non-valued
                    result[token] = ()
                elif tkl[i] == '(':
                    # multi-valued
                    i += 1  # Consume left parentheses
                    start = i
                    while i < l_len and tkl[i] != ')':
                        i += 1
                    result[token] = tuple([v for v in tkl[start:i] if v != '$'])
                    i += 1  # Consume right parentheses
                else:
                    # single-valued
                    result[token] = (tkl[i],)
                    i += 1  # Consume single value
        else:
            i += 1  # Consume unrecognized item
    return result


def parse_tokens(tokens, known_tokens):
    """Return (OID, found tokens), preserving the legacy tokenizer API."""
    if len(tokens) < 3 or tokens[0].strip() != '(' or tokens[-1].strip() != ')':
        raise ValueError(tokens)
    oid = tokens[1]
    result = {}
    i = 2
    while i < len(tokens):
        token = tokens[i]
        i += 1
        if token not in known_tokens or i >= len(tokens):
            continue
        if tokens[i] in known_tokens or tokens[i] == ')':
            value = ()
        elif tokens[i] == '(':
            i += 1
            start = i
            while i < len(tokens) and tokens[i] != ')':
                i += 1
            value = tuple(v for v in tokens[start:i] if v != '$')
            i += 1
        else:
            value = (tokens[i],)
            i += 1
        result[token] = value
    return oid, result
