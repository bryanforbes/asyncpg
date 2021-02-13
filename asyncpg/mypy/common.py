import mypy.nodes
import mypy.plugin
import mypy.types
import typing

from .. import compat

RECORD_NAME: compat.Final = 'asyncpg.protocol.protocol.Record'
MethodPairType = typing.Tuple[typing.List[mypy.nodes.Argument],
                              mypy.types.Type]
FieldPairType = typing.Tuple[str, mypy.types.Type]


class MethodHook(compat.Protocol):
    def __call__(self, __ctx: mypy.plugin.MethodContext) -> mypy.types.Type:
        ...


class AttributeHook(compat.Protocol):
    def __call__(self, __ctx: mypy.plugin.AttributeContext) -> mypy.types.Type:
        ...


class ClassDefHook(compat.Protocol):
    def __call__(self, __ctx: mypy.plugin.ClassDefContext) -> None:
        ...
