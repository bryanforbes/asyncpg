import asyncio
import asyncio.protocols
from codecs import CodecInfo
from hashlib import md5, sha256
import hmac
from typing import (
    Any,
    Callable,
    ClassVar,
    Dict,
    Generic,
    Iterable,
    Iterator,
    List,
    Optional,
    NewType,
    Set,
    Text,
    Tuple,
    Type as _TypingType,
    TypeVar,
    Union,
    overload,
)

import asyncpg.pgproto.pgproto

from ..compat import Final, Literal
from ..connect_utils import _ConnectionParameters
from ..pgproto.pgproto import WriteBuffer
from ..types import Type, Attribute

_NoTimeoutType = NewType('_NoTimeoutType', object)
_TimeoutType = Union[float, None, _NoTimeoutType]
_Record = TypeVar('_Record', bound='Record')
_OtherRecord = TypeVar('_OtherRecord', bound='Record')
_PreparedStatementState = TypeVar('_PreparedStatementState',
                                  bound='PreparedStatementState[Any]')

BUILTIN_TYPE_NAME_MAP: Final[Dict[str, int]]
BUILTIN_TYPE_OID_MAP: Final[Dict[int, str]]
NO_TIMEOUT: Final[_NoTimeoutType]

hashlib_md5 = md5

class ConnectionSettings(asyncpg.pgproto.pgproto.CodecContext):
    __pyx_vtable__: Any = ...
    def __init__(self, conn_key: Any) -> None: ...
    def add_python_codec(
        self,
        typeoid: int,
        typename: str,
        typeschema: str,
        typekind: str,
        encoder: Callable[[Any], Any],
        decoder: Callable[[Any], Any],
        format: Any,
    ) -> Any: ...
    def clear_type_cache(self) -> None: ...
    def get_data_codec(self, oid: int, format: Any = ..., ignore_custom_codec: bool = ...) -> Any: ...
    def get_text_codec(self) -> CodecInfo: ...
    def register_data_types(self, types: Iterable[Any]) -> None: ...
    def remove_python_codec(
        self, typeoid: int, typename: str, typeschema: str
    ) -> None: ...
    def set_builtin_type_codec(
        self,
        typeoid: int,
        typename: str,
        typeschema: str,
        typekind: str,
        alias_to: str,
        format: Any = ...,
    ) -> Any: ...
    def __getattr__(self, name: str) -> Any: ...
    def __reduce__(self) -> Any: ...

class PreparedStatementState(Generic[_Record]):
    closed: bool = ...
    name: str = ...
    query: str = ...
    refs: int = ...
    record_class: _TypingType[_Record] = ...
    ignore_custom_codec: bool = ...
    __pyx_vtable__: Any = ...
    def __init__(
        self,
        name: str,
        query: str,
        protocol: 'BaseProtocol[Any]',
        record_class: _TypingType[_Record],
        ignore_custom_codec: bool,
    ) -> None: ...
    def _get_parameters(self) -> Tuple[Type, ...]: ...
    def _get_attributes(self) -> Tuple[Attribute, ...]: ...
    def _init_types(self) -> Set[int]: ...
    def _init_codecs(self) -> None: ...
    def attach(self) -> None: ...
    def detach(self) -> None: ...
    def mark_closed(self) -> None: ...
    def __reduce__(self) -> Any: ...

class CoreProtocol:
    backend_pid: Any = ...
    backend_secret: Any = ...
    __pyx_vtable__: Any = ...
    def __init__(self, con_params: _ConnectionParameters) -> None: ...
    def is_in_transaction(self) -> bool: ...

class BaseProtocol(CoreProtocol, Generic[_Record]):
    queries_count: Any = ...
    __pyx_vtable__: Any = ...
    def __init__(
        self,
        addr: Any,
        connected_fut: Any,
        con_params: _ConnectionParameters,
        record_class: _TypingType[_Record],
        loop: Any,
    ) -> None: ...
    def set_connection(self, connection: Any) -> None: ...
    def get_server_pid(self, *args: Any, **kwargs: Any) -> int: ...
    def get_settings(self, *args: Any, **kwargs: Any) -> ConnectionSettings: ...
    def get_record_class(self) -> _TypingType[_Record]: ...
    def abort(self) -> None: ...
    async def bind(
        self,
        state: PreparedStatementState[_OtherRecord],
        args: Any,
        portal_name: str,
        timeout: _TimeoutType
    ) -> Any: ...
    @overload
    async def bind_execute(
        self,
        state: PreparedStatementState[_OtherRecord],
        args: Any,
        portal_name: str,
        limit: int,
        return_extra: Literal[False],
        timeout: _TimeoutType,
    ) -> List[_OtherRecord]: ...
    @overload
    async def bind_execute(
        self,
        state: PreparedStatementState[_OtherRecord],
        args: Any,
        portal_name: str,
        limit: int,
        return_extra: Literal[True],
        timeout: _TimeoutType,
    ) -> Tuple[List[_OtherRecord], bytes, bool]: ...
    @overload
    async def bind_execute(
        self,
        state: PreparedStatementState[_OtherRecord],
        args: Any,
        portal_name: str,
        limit: int,
        return_extra: bool,
        timeout: _TimeoutType,
    ) -> Union[List[_OtherRecord], Tuple[List[_OtherRecord], bytes, bool]]: ...
    async def bind_execute_many(
        self,
        state: PreparedStatementState[_OtherRecord],
        args: Any,
        portal_name: str,
        timeout: _TimeoutType
    ) -> None: ...
    async def close(self, timeout: _TimeoutType) -> None: ...
    def _get_timeout(self, timeout: _TimeoutType) -> Optional[float]: ...
    def _is_cancelling(self) -> bool: ...
    async def _wait_for_cancellation(self) -> None: ...
    async def close_statement(
        self,
        state: PreparedStatementState[_OtherRecord],
        timeout: _TimeoutType
    ) -> Any: ...
    async def copy_in(self, *args: Any, **kwargs: Any) -> str: ...
    async def copy_out(self, *args: Any, **kwargs: Any) -> str: ...
    async def execute(self, *args: Any, **kwargs: Any) -> Any: ...
    def is_closed(self, *args: Any, **kwargs: Any) -> Any: ...
    def is_connected(self, *args: Any, **kwargs: Any) -> Any: ...
    def is_in_transaction(self, *args: Any, **kwargs: Any) -> bool: ...
    def data_received(self, data: Any) -> None: ...
    def connection_made(self, transport: Any) -> None: ...
    def connection_lost(self, exc: Optional[Exception]) -> None: ...
    def pause_writing(self, *args: Any, **kwargs: Any) -> Any: ...
    @overload
    async def prepare(
        self,
        stmt_name: str,
        query: str,
        timeout: Optional[float] = ...,
        *,
        state: _PreparedStatementState,
        ignore_custom_codec: bool = ...,
        record_class: None
    ) -> _PreparedStatementState: ...
    @overload
    async def prepare(
        self,
        stmt_name: str,
        query: str,
        timeout: Optional[float] = ...,
        *,
        state: None = ...,
        ignore_custom_codec: bool = ...,
        record_class: _TypingType[_OtherRecord]
    ) -> PreparedStatementState[_OtherRecord]: ...
    @overload
    async def prepare(
        self,
        stmt_name: str,
        query: str,
        timeout: Optional[float] = ...,
        *,
        state: Optional[_PreparedStatementState] = ...,
        ignore_custom_codec: bool = ...,
        record_class: Optional[_TypingType[_OtherRecord]]
    ) -> Union[
        _PreparedStatementState,
        _TypingType[_OtherRecord]
    ]: ...
    async def query(self, *args: Any, **kwargs: Any) -> str: ...
    def resume_writing(self, *args: Any, **kwargs: Any) -> Any: ...
    def __reduce__(self) -> Any: ...

class Codec:
    __pyx_vtable__: Any = ...
    def __init__(
        self,
        name: str,
        schema: str,
        kind: str,
        type: int,
        format: int,
        xformat: int,
        c_encoder: Any,
    ) -> None: ...
    def __reduce__(self) -> Any: ...

class DataCodecConfig:
    __pyx_vtable__: Any = ...
    def __init__(self, cache_key: Any) -> None: ...
    def add_python_codec(
        self,
        typeoid: int,
        typename: str,
        typeschema: str,
        typekind: str,
        encoder: Callable[[ConnectionSettings, WriteBuffer, object], object],
        decoder: Callable[..., object],
        format: Any,
        xformat: Any,
    ) -> Any: ...
    def add_types(self, types: Iterable[Any]) -> Any: ...
    def clear_type_cache(self) -> None: ...
    def declare_fallback_codec(self, oid: int, name: str, schema: str) -> Codec: ...
    def remove_python_codec(
        self, typeoid: int, typename: str, typeschema: str
    ) -> Any: ...
    def set_builtin_type_codec(
        self,
        typeoid: int,
        typename: str,
        typeschema: str,
        typekind: str,
        alias_to: str,
        format: Any = ...,
    ) -> Any: ...
    def __reduce__(self) -> Any: ...

class Protocol(BaseProtocol[_Record], asyncio.protocols.Protocol): ...

_T = TypeVar('_T')

class Record:
    @overload
    def get(self, key: str) -> Optional[Any]: ...
    @overload
    def get(self, key: str, default: _T) -> Union[Any, _T]: ...
    def items(self) -> Iterator[Tuple[str, Any]]: ...
    def keys(self) -> Iterator[str]: ...
    def values(self) -> Iterator[Any]: ...
    @overload
    def __getitem__(self, index: str) -> Any: ...
    @overload
    def __getitem__(self, index: int) -> Any: ...
    @overload
    def __getitem__(self, index: slice) -> Tuple[Any, ...]: ...
    def __iter__(self) -> Iterator[Any]: ...
    def __contains__(self, x: object) -> bool: ...
    def __len__(self) -> int: ...

class Timer:
    def __init__(self, budget: Optional[float]) -> None: ...
    def __enter__(self) -> None: ...
    def __exit__(self, et: Any, e: Any, tb: Any) -> None: ...
    def get_remaining_budget(self) -> float: ...
    def has_budget_greater_than(self, amount: float) -> bool: ...

class SCRAMAuthentication:
    AUTHENTICATION_METHODS: ClassVar[List[str]]
    DEFAULT_CLIENT_NONCE_BYTES: ClassVar[int]
    DIGEST = sha256
    REQUIREMENTS_CLIENT_FINAL_MESSAGE: ClassVar[List[str]]
    REQUIREMENTS_CLIENT_PROOF: ClassVar[List[str]]
    SASLPREP_PROHIBITED: ClassVar[Tuple[Callable[[Text], bool], ...]]
    authentication_method: bytes
    authorization_message: Optional[bytes]
    client_channel_binding: bytes
    client_first_message_bare: Optional[bytes]
    client_nonce: Optional[bytes]
    client_proof: Optional[bytes]
    password_salt: Optional[bytes]
    password_iterations: int
    server_first_message: Optional[bytes]
    server_key: Optional[hmac.HMAC]
    server_nonce: Optional[bytes]
