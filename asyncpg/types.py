# Copyright (C) 2016-present the asyncpg authors and contributors
# <see AUTHORS file>
#
# This module is part of asyncpg and is released under
# the Apache 2.0 License: http://www.apache.org/licenses/LICENSE-2.0


import typing

from asyncpg.pgproto.types import (
    BitString, Point, Path, Polygon,
    Box, Line, LineSegment, Circle,
)


__all__ = (
    'Type', 'Attribute', 'Range', 'BitString', 'Point', 'Path', 'Polygon',
    'Box', 'Line', 'LineSegment', 'Circle', 'ServerVersion',
)


class Type(typing.NamedTuple):
    oid: int
    name: str
    kind: str
    schema: str


Type.__doc__ = 'Database data type.'
Type.oid.__doc__ = 'OID of the type.'
Type.name.__doc__ = 'Type name.  For example "int2".'
Type.kind.__doc__ = \
    'Type kind.  Can be "scalar", "array", "composite" or "range".'
Type.schema.__doc__ = 'Name of the database schema that defines the type.'


class Attribute(typing.NamedTuple):
    name: str
    type: Type


Attribute.__doc__ = 'Database relation attribute.'
Attribute.name.__doc__ = 'Attribute name.'
Attribute.type.__doc__ = 'Attribute data type :class:`asyncpg.types.Type`.'


class ServerVersion(typing.NamedTuple):
    major: int
    minor: int
    micro: int
    releaselevel: str
    serial: int


ServerVersion.__doc__ = 'PostgreSQL server version tuple.'

T = typing.TypeVar('T')


class Range(typing.Generic[T]):
    """Immutable representation of PostgreSQL `range` type."""

    __slots__ = '_lower', '_upper', '_lower_inc', '_upper_inc', '_empty'

    def __init__(self, lower: typing.Optional[T] = None,
                 upper: typing.Optional[T] = None, *,
                 lower_inc: bool = True,
                 upper_inc: bool = False,
                 empty: bool = False) -> None:
        self._empty = empty
        if empty:
            self._lower = self._upper = None
            self._lower_inc = self._upper_inc = False
        else:
            self._lower = lower
            self._upper = upper
            self._lower_inc = lower is not None and lower_inc
            self._upper_inc = upper is not None and upper_inc

    @property
    def lower(self) -> typing.Optional[T]:
        return self._lower

    @property
    def lower_inc(self) -> bool:
        return self._lower_inc

    @property
    def lower_inf(self) -> bool:
        return self._lower is None and not self._empty

    @property
    def upper(self) -> typing.Optional[T]:
        return self._upper

    @property
    def upper_inc(self) -> bool:
        return self._upper_inc

    @property
    def upper_inf(self) -> bool:
        return self._upper is None and not self._empty

    @property
    def isempty(self) -> bool:
        return self._empty

    def __bool__(self) -> bool:
        return not self._empty

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Range):
            return NotImplemented

        return (
            self._lower,
            self._upper,
            self._lower_inc,
            self._upper_inc,
            self._empty
        ) == (
            other._lower,
            other._upper,
            other._lower_inc,
            other._upper_inc,
            other._empty
        )

    def __hash__(self) -> int:
        return hash((
            self._lower,
            self._upper,
            self._lower_inc,
            self._upper_inc,
            self._empty
        ))

    def __repr__(self) -> str:
        if self._empty:
            desc = 'empty'
        else:
            if self._lower is None or not self._lower_inc:
                lb = '('
            else:
                lb = '['

            if self._lower is not None:
                lb += repr(self._lower)

            if self._upper is not None:
                ub = repr(self._upper)
            else:
                ub = ''

            if self._upper is None or not self._upper_inc:
                ub += ')'
            else:
                ub += ']'

            desc = '{}, {}'.format(lb, ub)

        return '<Range {}>'.format(desc)

    __str__ = __repr__
