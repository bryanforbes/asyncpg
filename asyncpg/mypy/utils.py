import collections
import mypy.nodes
import mypy.plugin
import mypy.semanal
import mypy.types
import mypy.typevars
import mypy.util
import typing

from . import common


def is_record(info: mypy.nodes.TypeInfo) -> bool:
    metadata = info.metadata.get('asyncpg')

    if metadata and metadata.get('is_record'):
        return True

    return False


def mark_record(info: mypy.nodes.TypeInfo) -> None:
    info.metadata.setdefault('asyncpg', {})['is_record'] = True


def get_record_fields(ctx: mypy.plugin.ClassDefContext,
                      defn: mypy.nodes.ClassDef) \
        -> typing.Optional[typing.Deque[common.FieldPairType]]:
    pairs: typing.Deque[common.FieldPairType] = collections.deque()

    for base in defn.info.mro:
        if base.fullname == common.RECORD_NAME:
            break

        for stmt in reversed(base.defn.defs.body):
            if isinstance(stmt, mypy.nodes.AssignmentStmt) and \
                    isinstance(stmt.lvalues[0], mypy.nodes.NameExpr):
                name = stmt.lvalues[0].name

                if stmt.type is None:
                    pairs.appendleft((name, mypy.types.AnyType(
                        mypy.types.TypeOfAny.unannotated)))
                else:
                    analyzed = ctx.api.anal_type(stmt.type)
                    if analyzed is None:
                        # return None to signal that we should defer for
                        # another semantic analysis sweep
                        return None
                    pairs.appendleft((name, analyzed))

    return pairs


def get_record_field_names(defn: mypy.nodes.ClassDef) \
        -> typing.Deque[str]:
    names: typing.Deque[str] = collections.deque()

    for base in defn.info.mro:
        if base.fullname == common.RECORD_NAME:
            break

        for stmt in reversed(base.defn.defs.body):
            if isinstance(stmt, mypy.nodes.AssignmentStmt) and \
                    isinstance(stmt.lvalues[0], mypy.nodes.NameExpr):
                names.appendleft(stmt.lvalues[0].name)

    return names


def get_record_slice_types(names: typing.Sequence[str],
                           info: mypy.nodes.TypeInfo) \
        -> typing.List[mypy.types.Type]:
    result: typing.List[mypy.types.Type] = []

    for name in names:
        node = info.get(name)
        assert node is not None and node.type is not None
        result.append(node.type)

    return result


def add_type_var(ctx: mypy.plugin.ClassDefContext,
                 name: str) -> typing.Tuple[mypy.types.TypeVarDef,
                                            mypy.types.TypeVarType]:
    object_type = ctx.api.named_type('__builtins__.object')
    tvd = mypy.types.TypeVarDef(name,
                                ctx.cls.info.fullname + '.' + name,
                                -1, [], object_type)
    tvd_type = mypy.types.TypeVarType(tvd)
    tvar_expr = mypy.nodes.TypeVarExpr(name,
                                       ctx.cls.info.fullname + '.' + name,
                                       [], object_type)

    ctx.cls.info.names[name] = mypy.nodes.SymbolTableNode(mypy.nodes.MDEF,
                                                          tvar_expr)

    return tvd, tvd_type


def create_argument(name: str, typ: mypy.types.Type, kind: int) \
        -> mypy.nodes.Argument:
    var = mypy.nodes.Var(name, typ)
    return mypy.nodes.Argument(variable=var,
                               type_annotation=typ,
                               initializer=None,
                               kind=kind)


def create_decorator(info: mypy.nodes.TypeInfo,
                     name: str,
                     args: typing.List[mypy.nodes.Argument],
                     return_type: mypy.types.Type,
                     self_type: typing.Optional[mypy.types.Type],
                     function_type: mypy.types.Instance,
                     tvar_def: typing.Optional[mypy.types.TypeVarDef]) \
        -> mypy.nodes.Decorator:
    func = create_func_def(info, name, args, return_type, self_type,
                           function_type, tvar_def)
    func.is_decorated = True

    decorator = mypy.nodes.Decorator(func, [], mypy.nodes.Var(name))
    decorator.set_line(info)

    return decorator


def create_func_def(info: mypy.nodes.TypeInfo,
                    name: str,
                    args: typing.List[mypy.nodes.Argument],
                    return_type: mypy.types.Type,
                    self_type: typing.Optional[mypy.types.Type],
                    function_type: mypy.types.Instance,
                    tvar_def: typing.Optional[mypy.types.TypeVarDef]) \
        -> mypy.nodes.FuncDef:
    args = [mypy.nodes.Argument(mypy.nodes.Var('self'), self_type, None,
                                mypy.nodes.ARG_POS)] + args
    arg_types, arg_names, arg_kinds = [], [], []

    for arg in args:
        assert arg.type_annotation, 'All arguments must be fully typed.'
        arg_types.append(arg.type_annotation)
        arg_names.append(arg.variable.name)
        arg_kinds.append(arg.kind)

    signature = mypy.types.CallableType(arg_types, arg_kinds, arg_names,
                                        return_type, function_type)
    if tvar_def:
        signature.variables = [tvar_def]

    func = mypy.nodes.FuncDef(name, args,
                              mypy.nodes.Block([mypy.nodes.PassStmt()]))
    func.info = info
    func.type = mypy.semanal.set_callable_name(signature, func)
    func._fullname = info.fullname + '.' + name
    func.line = info.line

    return func


def add_overloads_to_class(ctx: mypy.plugin.ClassDefContext,
                           cls: mypy.nodes.ClassDef,
                           name: str,
                           args_return_pairs: typing.Iterable[
                               typing.Tuple[typing.List[mypy.nodes.Argument],
                                            mypy.types.Type]
                           ],
                           impl: typing.Tuple[typing.List[mypy.nodes.Argument],
                                              mypy.types.Type],
                           self_type: typing.Optional[mypy.types.Type] = None,
                           tvar_def: typing.Optional[
                               mypy.types.TypeVarDef] = None) -> None:
    info = cls.info

    # First remove any previously generated overloads with the same name
    # to avoid clashes and problems in the semantic analyzer.
    if name in info.names:
        sym = info.names[name]
        if sym.plugin_generated and \
                isinstance(sym.node, mypy.nodes.OverloadedFuncDef):
            cls.defs.body.remove(sym.node)

    self_type = self_type or mypy.typevars.fill_typevars(info)
    function_type = ctx.api.named_type('__builtins__.function')

    overloads: typing.List[mypy.nodes.OverloadPart] = [
        create_decorator(info, name, args,
                         return_type, self_type,
                         function_type, tvar_def)
        for args, return_type in args_return_pairs]

    overload_func_def = mypy.nodes.OverloadedFuncDef(overloads)
    overload_func_def.info = info
    overload_func_def.type = mypy.types.Overloaded([
        typing.cast(mypy.types.CallableType, decorator.func.type)
        for decorator in typing.cast(typing.List[mypy.nodes.Decorator],
                                     overloads)
    ])

    overload_func_def.impl = create_func_def(info, name, impl[0], impl[1],
                                             self_type, function_type,
                                             tvar_def)

    # NOTE: we would like the plugin generated node to dominate, but we still
    # need to keep any existing definitions so they get semantically analyzed.
    if name in info.names and not info.names[name].plugin_generated:
        # Get a nice unique name instead.
        r_name = mypy.util.get_unique_redefinition_name(name, info.names)
        info.names[r_name] = info.names[name]

    info.names[name] = mypy.nodes.SymbolTableNode(mypy.nodes.MDEF,
                                                  overload_func_def,
                                                  plugin_generated=True)
    info.defn.defs.body.append(overload_func_def)


def get_argument_type_by_name(ctx: typing.Union[mypy.plugin.FunctionContext,
                                                mypy.plugin.MethodContext],
                              name: str) \
        -> typing.Optional[mypy.types.Type]:
    if name not in ctx.callee_arg_names:
        return None

    index = ctx.callee_arg_names.index(name)
    arg_types = ctx.arg_types[index]

    if len(arg_types) != 1:
        return None

    return arg_types[0]


def slice_index_to_int(slice_index: typing.Optional[mypy.nodes.Expression]) \
        -> typing.Optional[int]:
    result: typing.Optional[int] = None

    if isinstance(slice_index, mypy.nodes.IntExpr):
        result = slice_index.value
    elif isinstance(slice_index, mypy.nodes.UnaryExpr):
        if isinstance(slice_index.expr, mypy.nodes.IntExpr):
            result = slice_index.expr.value
        if result is not None and slice_index.op == '-':
            result = result * -1

    return result
