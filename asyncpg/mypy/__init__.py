import typing
import mypy.nodes
import mypy.plugin
import mypy.types

from . import common
from . import hooks
from . import utils


class AsyncpgPlugin(mypy.plugin.Plugin):
    def get_method_hook(self, fullname: str) \
            -> typing.Optional[common.MethodHook]:
        class_name, _, method_name = fullname.rpartition('.')
        symbol = self.lookup_fully_qualified(class_name)

        if symbol and isinstance(symbol.node, mypy.nodes.TypeInfo) and \
                utils.is_record(symbol.node):
            if method_name == '__getitem__':
                return hooks.record_getitem
            if method_name == 'get':
                return hooks.record_get

        return None

    def get_attribute_hook(self, fullname: str) \
            -> typing.Optional[common.AttributeHook]:
        class_name, _, _ = fullname.rpartition('.')
        symbol = self.lookup_fully_qualified(class_name)

        if symbol is not None and \
                isinstance(symbol.node, mypy.nodes.TypeInfo) and \
                utils.is_record(symbol.node):
            return hooks.record_attribute

        return None

    def get_customize_class_mro_hook(self, fullname: str) \
            -> typing.Optional[common.ClassDefHook]:
        return hooks.mark_record


def plugin(version: str) -> typing.Type[mypy.plugin.Plugin]:
    return AsyncpgPlugin
