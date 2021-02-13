import mypy.nodes
import mypy.plugin
import mypy.types
import typing

from . import common
from . import utils


def mark_record(ctx: mypy.plugin.ClassDefContext) -> None:
    if ctx.cls.info.fullname == common.RECORD_NAME:
        return

    if ctx.cls.info.has_base(common.RECORD_NAME):
        utils.mark_record(ctx.cls.info)


def record_attribute(ctx: mypy.plugin.AttributeContext) \
        -> mypy.types.Type:
    if isinstance(ctx.type, mypy.types.Instance) and \
            utils.is_record(ctx.type.type):
        assert isinstance(ctx.context, mypy.nodes.MemberExpr)

        # raise an error when users try to access the keys defined
        # using attribute notation
        ctx.api.fail('"{}" has no attribute "{}"'
                     .format(ctx.type.type.name, ctx.context.name),
                     ctx.context)

    return ctx.default_attr_type


def record_getitem(ctx: mypy.plugin.MethodContext) \
        -> mypy.types.Type:
    if isinstance(ctx.type, mypy.types.Instance):
        arg = ctx.args[0][0]
        arg_type = ctx.arg_types[0][0]

        if arg_type is not None and isinstance(arg_type, mypy.types.Instance):
            if isinstance(arg_type.last_known_value, mypy.types.LiteralType):
                value = arg_type.last_known_value.value
                names = utils.get_record_field_names(ctx.type.type.defn)
                name: typing.Optional[str] = None

                if isinstance(value, int) and value < len(names):
                    name = names[value]
                elif isinstance(value, str) and value in names:
                    name = value

                if name is None:
                    is_int = isinstance(value, int)
                    formatted_key = value if is_int else \
                        "'{}'".format(value)
                    ctx.api.fail('Record "{}" has no {} {}'
                                 .format(ctx.type.type.name,
                                         'index' if is_int else 'key',
                                         formatted_key),
                                 ctx.context)
                else:
                    node = ctx.type.type.get(name)

                    if node is not None and node.type is not None:
                        return node.type
            elif arg_type.type.has_base('builtins.slice') and \
                    isinstance(arg, mypy.nodes.SliceExpr):
                names_list = list(utils.get_record_field_names(
                    ctx.type.type.defn
                ))
                begin_index = utils.slice_index_to_int(arg.begin_index)
                end_index = utils.slice_index_to_int(arg.end_index)
                stride = utils.slice_index_to_int(arg.stride)

                return mypy.types.TupleType(
                    utils.get_record_slice_types(
                        names_list[begin_index:end_index:stride],
                        ctx.type.type
                    ),
                    ctx.api.named_generic_type(
                        'builtins.tuple',
                        [mypy.types.AnyType(mypy.types.TypeOfAny.special_form)]
                    )
                )

    return ctx.default_return_type


def record_get(ctx: mypy.plugin.MethodContext) \
        -> mypy.types.Type:
    if ctx.arg_names[0][0] is not None or \
            len(ctx.arg_names) > 1 and \
            ctx.arg_names[1][0] is not None:
        ctx.api.fail('get() takes no keyword arguments', ctx.context)
    elif isinstance(ctx.type, mypy.types.Instance):
        arg = utils.get_argument_type_by_name(ctx, 'key')
        default_arg = utils.get_argument_type_by_name(ctx, 'default')

        if arg and isinstance(arg, mypy.types.Instance) and \
                isinstance(arg.last_known_value, mypy.types.LiteralType):
            value = arg.last_known_value.value
            names = utils.get_record_field_names(ctx.type.type.defn)
            name: typing.Optional[str] = None

            if isinstance(value, str) and value in names:
                name = value

            if name is None:
                if default_arg is not None:
                    return default_arg

                ctx.api.fail('Record "{}" has no key \'{}\''
                             .format(ctx.type.type.name, value),
                             ctx.context)
            else:
                node = ctx.type.type.get(name)

                if node is not None and node.type is not None:
                    return node.type

    return ctx.default_return_type
