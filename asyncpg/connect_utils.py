# Copyright (C) 2016-present the asyncpg authors and contributors
# <see AUTHORS file>
#
# This module is part of asyncpg and is released under
# the Apache 2.0 License: http://www.apache.org/licenses/LICENSE-2.0


import asyncio
import functools
import getpass
import os
import pathlib
import platform
import re
import socket
import ssl as ssl_module
import stat
import struct
import time
import typing
import urllib.parse
import warnings
import inspect

from . import compat
from . import exceptions
from . import protocol

_Connection = typing.TypeVar('_Connection')
_Protocol = typing.TypeVar('_Protocol', bound=asyncio.Protocol)
_Record = typing.TypeVar('_Record', bound=protocol.Record)

_TPTupleType = typing.Tuple[asyncio.WriteTransport, _Protocol]
AddrType = typing.Union[typing.Tuple[str, int], str]
SSLStringValues = compat.Literal[
    'disable', 'prefer', 'allow', 'require', 'verify-ca', 'verify-full'
]
_ParsedSSLType = typing.Union[
    ssl_module.SSLContext, compat.Literal[False]
]
SSLType = typing.Union[_ParsedSSLType, SSLStringValues, bool]
HostType = typing.Union[typing.List[str], str]
PortType = typing.Union[typing.List[int], int]


class _ConnectionParameters(typing.NamedTuple):
    user: str
    password: typing.Optional[str]
    database: str
    ssl: typing.Optional[_ParsedSSLType]
    ssl_is_advisory: typing.Optional[bool]
    connect_timeout: typing.Optional[float]
    server_settings: typing.Optional[typing.Dict[str, str]]


class _ClientConfiguration(typing.NamedTuple):
    command_timeout: typing.Optional[float]
    statement_cache_size: int
    max_cached_statement_lifetime: int
    max_cacheable_statement_size: int


_system: compat.Final = platform.uname().system
PGPASSFILE: compat.Final = 'pgpass.conf' if _system == 'Windows' else '.pgpass'


def _read_password_file(passfile: pathlib.Path) \
        -> typing.List[typing.Tuple[str, ...]]:

    passtab = []

    try:
        if not passfile.exists():
            return []

        if not passfile.is_file():
            warnings.warn(
                'password file {!r} is not a plain file'.format(passfile))

            return []

        if _system != 'Windows':
            if passfile.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                warnings.warn(
                    'password file {!r} has group or world access; '
                    'permissions should be u=rw (0600) or less'.format(
                        passfile))

                return []

        with passfile.open('rt') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    # Skip empty lines and comments.
                    continue
                # Backslash escapes both itself and the colon,
                # which is a record separator.
                line = line.replace(R'\\', '\n')
                passtab.append(tuple(
                    p.replace('\n', R'\\')
                    for p in re.split(r'(?<!\\):', line, maxsplit=4)
                ))
    except IOError:
        pass

    return passtab


def _read_password_from_pgpass(
        *, passfile: pathlib.Path,
        hosts: typing.List[str],
        ports: typing.List[int],
        database: str,
        user: str) -> typing.Optional[str]:
    """Parse the pgpass file and return the matching password.

    :return:
        Password string, if found, ``None`` otherwise.
    """

    passtab = _read_password_file(passfile)
    if not passtab:
        return None

    for host, port in zip(hosts, ports):
        if host.startswith('/'):
            # Unix sockets get normalized into 'localhost'
            host = 'localhost'

        for phost, pport, pdatabase, puser, ppassword in passtab:
            if phost != '*' and phost != host:
                continue
            if pport != '*' and pport != str(port):
                continue
            if pdatabase != '*' and pdatabase != database:
                continue
            if puser != '*' and puser != user:
                continue

            # Found a match.
            return ppassword

    return None


def _validate_port_spec(hosts: typing.List[str],
                        port: PortType) \
        -> typing.List[int]:
    if isinstance(port, list):
        # If there is a list of ports, its length must
        # match that of the host list.
        if len(port) != len(hosts):
            raise exceptions.InterfaceError(
                'could not match {} port numbers to {} hosts'.format(
                    len(port), len(hosts)))
    else:
        port = [port for _ in range(len(hosts))]

    return port


def _parse_hostlist(hostlist: str,
                    port: typing.Optional[PortType],
                    *, unquote: bool = False) \
        -> typing.Tuple[typing.List[str], typing.List[int]]:
    if ',' in hostlist:
        # A comma-separated list of host addresses.
        hostspecs = hostlist.split(',')
    else:
        hostspecs = [hostlist]

    hosts: typing.List[str] = []
    hostlist_ports: typing.List[int] = []
    ports: typing.Optional[typing.List[int]] = None

    if not port:
        portspec = os.environ.get('PGPORT')
        if portspec:
            if ',' in portspec:
                temp_port: typing.Union[typing.List[int], int] = [
                    int(p) for p in portspec.split(',')]
            else:
                temp_port = int(portspec)
        else:
            temp_port = 5432

        default_port = _validate_port_spec(hostspecs, temp_port)

    else:
        ports = _validate_port_spec(hostspecs, port)

    for i, hostspec in enumerate(hostspecs):
        if not hostspec.startswith('/'):
            addr, _, hostspec_port = hostspec.partition(':')
        else:
            addr = hostspec
            hostspec_port = ''

        if unquote:
            addr = urllib.parse.unquote(addr)

        hosts.append(addr)
        if not port:
            if hostspec_port:
                if unquote:
                    hostspec_port = urllib.parse.unquote(hostspec_port)
                hostlist_ports.append(int(hostspec_port))
            else:
                hostlist_ports.append(default_port[i])

    if not ports:
        ports = hostlist_ports

    return hosts, ports


def _parse_connect_dsn_and_args(*, dsn: typing.Optional[str],
                                host: typing.Optional[HostType],
                                port: typing.Optional[PortType],
                                user: typing.Optional[str],
                                password: typing.Optional[str],
                                passfile: typing.Optional[str],
                                database: typing.Optional[str],
                                ssl: typing.Optional[SSLType],
                                connect_timeout: typing.Optional[float],
                                server_settings: typing.Dict[str, str]) \
        -> typing.Tuple[typing.List[typing.Union[typing.Tuple[str, int], str]],
                        _ConnectionParameters]:
    # `auth_hosts` is the version of host information for the purposes
    # of reading the pgpass file.
    auth_hosts = None
    ssl_val: typing.Optional[typing.Union[SSLType, str]] = ssl

    if dsn:
        parsed = urllib.parse.urlparse(dsn)

        if parsed.scheme not in {'postgresql', 'postgres'}:
            raise ValueError(
                'invalid DSN: scheme is expected to be either '
                '"postgresql" or "postgres", got {!r}'.format(parsed.scheme))

        if parsed.netloc:
            if '@' in parsed.netloc:
                dsn_auth, _, dsn_hostspec = parsed.netloc.partition('@')
            else:
                dsn_hostspec = parsed.netloc
                dsn_auth = ''
        else:
            dsn_auth = dsn_hostspec = ''

        if dsn_auth:
            dsn_user, _, dsn_password = dsn_auth.partition(':')
        else:
            dsn_user = dsn_password = ''

        if not host and dsn_hostspec:
            host, port = _parse_hostlist(dsn_hostspec, port, unquote=True)

        if parsed.path and database is None:
            dsn_database = parsed.path
            if dsn_database.startswith('/'):
                dsn_database = dsn_database[1:]
            database = urllib.parse.unquote(dsn_database)

        if user is None and dsn_user:
            user = urllib.parse.unquote(dsn_user)

        if password is None and dsn_password:
            password = urllib.parse.unquote(dsn_password)

        if parsed.query:
            query = urllib.parse.parse_qs(parsed.query, strict_parsing=True)
            query_str: typing.Dict[str, str] = {}
            for key, val in query.items():
                if isinstance(val, list):
                    query_str[key] = val[-1]

            if 'port' in query_str:
                val_str = query_str.pop('port')
                if not port and val:
                    port = [int(p) for p in val_str.split(',')]

            if 'host' in query_str:
                val_str = query_str.pop('host')
                if not host and val_str:
                    host, port = _parse_hostlist(val_str, port)

            if 'dbname' in query_str:
                val_str = query_str.pop('dbname')
                if database is None:
                    database = val_str

            if 'database' in query_str:
                val_str = query_str.pop('database')
                if database is None:
                    database = val_str

            if 'user' in query_str:
                val_str = query_str.pop('user')
                if user is None:
                    user = val_str

            if 'password' in query_str:
                val_str = query_str.pop('password')
                if password is None:
                    password = val_str

            if 'passfile' in query_str:
                val_str = query_str.pop('passfile')
                if passfile is None:
                    passfile = val_str

            if 'sslmode' in query_str:
                val_str = query_str.pop('sslmode')
                if ssl_val is None:
                    ssl_val = val_str

            if query_str:
                if server_settings is None:
                    server_settings = query_str
                else:
                    server_settings = {**query_str, **server_settings}

    if not host:
        hostspec = os.environ.get('PGHOST')
        if hostspec:
            host, port = _parse_hostlist(hostspec, port)

    if not host:
        auth_hosts = ['localhost']

        if _system == 'Windows':
            host = ['localhost']
        else:
            host = ['/run/postgresql', '/var/run/postgresql',
                    '/tmp', '/private/tmp', 'localhost']

    if not isinstance(host, list):
        host = [host]

    if auth_hosts is None:
        auth_hosts = host

    if not port:
        portspec = os.environ.get('PGPORT')
        if portspec:
            if ',' in portspec:
                port = [int(p) for p in portspec.split(',')]
            else:
                port = int(portspec)
        else:
            port = 5432

    elif isinstance(port, (list, tuple)):
        port = [int(p) for p in port]

    else:
        port = int(port)

    port = _validate_port_spec(host, port)

    if user is None:
        user = os.getenv('PGUSER')
        if not user:
            user = getpass.getuser()

    if password is None:
        password = os.getenv('PGPASSWORD')

    if database is None:
        database = os.getenv('PGDATABASE')

    if database is None:
        database = user

    if user is None:
        raise exceptions.InterfaceError(
            'could not determine user name to connect with')

    if database is None:
        raise exceptions.InterfaceError(
            'could not determine database name to connect to')

    if password is None:
        if passfile is None:
            passfile = os.getenv('PGPASSFILE')

        if passfile is None:
            homedir = compat.get_pg_home_directory()
            if homedir:
                passfile_path: typing.Optional[
                    pathlib.Path
                ] = homedir / PGPASSFILE
            else:
                passfile_path = None
        else:
            passfile_path = pathlib.Path(passfile)

        if passfile_path is not None:
            password = _read_password_from_pgpass(
                hosts=auth_hosts, ports=port,
                database=database, user=user,
                passfile=passfile_path)

    addrs: typing.List[AddrType] = []
    have_tcp_addrs = False
    for h, p in zip(host, port):
        if h.startswith('/'):
            # UNIX socket name
            if '.s.PGSQL.' not in h:
                h = os.path.join(h, '.s.PGSQL.{}'.format(p))
            addrs.append(h)
        else:
            # TCP host/port
            addrs.append((h, p))
            have_tcp_addrs = True

    if not addrs:
        raise ValueError(
            'could not determine the database address to connect to')

    if ssl_val is None:
        ssl_val = os.getenv('PGSSLMODE')

    if ssl_val is None and have_tcp_addrs:
        ssl_val = 'prefer'

    # ssl_is_advisory is only allowed to come from the sslmode parameter.
    ssl_is_advisory = None
    if isinstance(ssl_val, str):
        SSLMODES = {
            'disable': 0,
            'allow': 1,
            'prefer': 2,
            'require': 3,
            'verify-ca': 4,
            'verify-full': 5,
        }
        try:
            sslmode = SSLMODES[ssl_val]
        except KeyError:
            modes = ', '.join(SSLMODES.keys())
            raise exceptions.InterfaceError(
                '`sslmode` parameter must be one of: {}'.format(modes))

        # sslmode 'allow' is currently handled as 'prefer' because we're
        # missing the "retry with SSL" behavior for 'allow', but do have the
        # "retry without SSL" behavior for 'prefer'.
        # Not changing 'allow' to 'prefer' here would be effectively the same
        # as changing 'allow' to 'disable'.
        if sslmode == SSLMODES['allow']:
            sslmode = SSLMODES['prefer']

        # docs at https://www.postgresql.org/docs/10/static/libpq-connect.html
        # Not implemented: sslcert & sslkey & sslrootcert & sslcrl params.
        if sslmode <= SSLMODES['allow']:
            ssl = False
            ssl_is_advisory = sslmode >= SSLMODES['allow']
        else:
            ssl = ssl_module.create_default_context()
            ssl.check_hostname = sslmode >= SSLMODES['verify-full']
            ssl.verify_mode = ssl_module.CERT_REQUIRED
            if sslmode <= SSLMODES['require']:
                ssl.verify_mode = ssl_module.CERT_NONE
            ssl_is_advisory = sslmode <= SSLMODES['prefer']
    elif ssl is True:
        ssl = ssl_module.create_default_context()

    if server_settings is not None and (
            not isinstance(server_settings, dict) or
            not all(isinstance(k, str) for k in server_settings) or
            not all(isinstance(v, str) for v in server_settings.values())):
        raise ValueError(
            'server_settings is expected to be None or '
            'a Dict[str, str]')

    params = _ConnectionParameters(
        user=user, password=password, database=database,
        ssl=typing.cast(_ParsedSSLType, ssl),
        ssl_is_advisory=ssl_is_advisory, connect_timeout=connect_timeout,
        server_settings=server_settings)

    return addrs, params


def _parse_connect_arguments(*, dsn: typing.Optional[str],
                             host: typing.Optional[HostType],
                             port: typing.Optional[PortType],
                             user: typing.Optional[str],
                             password: typing.Optional[str],
                             passfile: typing.Optional[str],
                             database: typing.Optional[str],
                             timeout: typing.Optional[float],
                             command_timeout: typing.Optional[
                                 typing.Union[float, typing.SupportsFloat]],
                             statement_cache_size: int,
                             max_cached_statement_lifetime: int,
                             max_cacheable_statement_size: int,
                             ssl: typing.Optional[SSLType],
                             server_settings: typing.Dict[str, str]) \
        -> typing.Tuple[typing.List[AddrType], _ConnectionParameters,
                        _ClientConfiguration]:

    local_vars = locals()
    for var_name in {'max_cacheable_statement_size',
                     'max_cached_statement_lifetime',
                     'statement_cache_size'}:
        var_val = local_vars[var_name]
        if var_val is None or isinstance(var_val, bool) or var_val < 0:
            raise ValueError(
                '{} is expected to be greater '
                'or equal to 0, got {!r}'.format(var_name, var_val))

    if command_timeout is not None:
        try:
            if isinstance(command_timeout, bool):
                raise ValueError
            command_timeout = float(command_timeout)
            if command_timeout <= 0:
                raise ValueError
        except ValueError:
            raise ValueError(
                'invalid command_timeout value: '
                'expected greater than 0 float (got {!r})'.format(
                    command_timeout)) from None

    addrs, params = _parse_connect_dsn_and_args(
        dsn=dsn, host=host, port=port, user=user,
        password=password, passfile=passfile, ssl=ssl,
        database=database, connect_timeout=timeout,
        server_settings=server_settings)

    config = _ClientConfiguration(
        command_timeout=command_timeout,
        statement_cache_size=statement_cache_size,
        max_cached_statement_lifetime=max_cached_statement_lifetime,
        max_cacheable_statement_size=max_cacheable_statement_size,)

    return addrs, params, config


class TLSUpgradeProto(asyncio.Protocol):
    def __init__(self, loop: typing.Optional[asyncio.AbstractEventLoop],
                 host: str, port: int, ssl_context: ssl_module.SSLContext,
                 ssl_is_advisory: typing.Optional[bool]) -> None:
        self.on_data = _create_future(loop)
        self.host = host
        self.port = port
        self.ssl_context = ssl_context
        self.ssl_is_advisory = ssl_is_advisory

    def data_received(self, data: bytes) -> None:
        if data == b'S':
            self.on_data.set_result(True)
        elif (self.ssl_is_advisory and
                self.ssl_context.verify_mode == ssl_module.CERT_NONE and
                data == b'N'):
            # ssl_is_advisory will imply that ssl.verify_mode == CERT_NONE,
            # since the only way to get ssl_is_advisory is from
            # sslmode=prefer (or sslmode=allow). But be extra sure to
            # disallow insecure connections when the ssl context asks for
            # real security.
            self.on_data.set_result(False)
        else:
            self.on_data.set_exception(
                ConnectionError(
                    'PostgreSQL server at "{host}:{port}" '
                    'rejected SSL upgrade'.format(
                        host=self.host, port=self.port)))

    def connection_lost(self, exc: typing.Optional[Exception]) -> None:
        if not self.on_data.done():
            if exc is None:
                exc = ConnectionError('unexpected connection_lost() call')
            self.on_data.set_exception(exc)


async def _create_ssl_connection(
    protocol_factory: typing.Callable[[], _Protocol],
    host: str,
    port: int,
    *,
    loop: asyncio.AbstractEventLoop,
    ssl_context: ssl_module.SSLContext,
    ssl_is_advisory: typing.Optional[bool] = False
) -> _TPTupleType[_Protocol]:

    tr, pr = typing.cast(
        typing.Tuple[asyncio.WriteTransport, TLSUpgradeProto],
        await loop.create_connection(
            lambda: TLSUpgradeProto(loop, host, port,
                                    ssl_context, ssl_is_advisory),
            host, port))

    tr.write(struct.pack('!ll', 8, 80877103))  # SSLRequest message.

    try:
        do_ssl_upgrade = await pr.on_data
    except (Exception, asyncio.CancelledError):
        tr.close()
        raise

    if hasattr(loop, 'start_tls'):
        if do_ssl_upgrade:
            try:
                new_tr = typing.cast(
                    asyncio.WriteTransport,
                    await typing.cast(typing.Any, loop).start_tls(
                        tr, pr,
                        ssl_context,
                        server_hostname=host))
            except (Exception, asyncio.CancelledError):
                tr.close()
                raise
        else:
            new_tr = tr

        pg_proto = protocol_factory()
        pg_proto.connection_made(new_tr)
        new_tr.set_protocol(pg_proto)

        return new_tr, pg_proto
    else:
        conn_factory = functools.partial(
            loop.create_connection, protocol_factory)

        if do_ssl_upgrade:
            conn_factory = functools.partial(
                conn_factory, ssl=ssl_context, server_hostname=host)

        sock = _get_socket(tr)
        sock = sock.dup()
        _set_nodelay(sock)
        tr.close()

        try:
            return typing.cast(
                typing.Tuple[asyncio.WriteTransport, _Protocol],
                await conn_factory(sock=sock)
            )
        except (Exception, asyncio.CancelledError):
            sock.close()
            raise


async def _connect_addr(
    *,
    addr: AddrType,
    loop: asyncio.AbstractEventLoop,
    timeout: float,
    params: _ConnectionParameters,
    config: _ClientConfiguration,
    connection_class: typing.Type[_Connection],
    record_class: typing.Type[_Record]
) -> _Connection:
    assert loop is not None

    if timeout <= 0:
        raise asyncio.TimeoutError

    connected = _create_future(loop)

    params_input = params
    if callable(params.password):
        if inspect.iscoroutinefunction(params.password):
            password = await params.password()
        else:
            password = params.password()

        params = params._replace(password=password)

    proto_factory = lambda: protocol.Protocol(
        addr, connected, params, record_class, loop)

    if isinstance(addr, str):
        connector = typing.cast(
            typing.Coroutine[typing.Any, None,
                             _TPTupleType['protocol.Protocol[_Record]']],
            loop.create_unix_connection(proto_factory, addr)
        )
    elif params.ssl:
        connector = _create_ssl_connection(
            proto_factory, *addr, loop=loop,
            ssl_context=params.ssl,
            ssl_is_advisory=params.ssl_is_advisory)
    else:
        connector = typing.cast(
            typing.Coroutine[typing.Any, None,
                             _TPTupleType['protocol.Protocol[_Record]']],
            loop.create_connection(proto_factory, *addr))

    connector_future = asyncio.ensure_future(connector)
    before = time.monotonic()
    tr, pr = await compat.wait_for(connector_future, timeout=timeout)
    timeout -= time.monotonic() - before

    try:
        if timeout <= 0:
            raise asyncio.TimeoutError
        await compat.wait_for(connected, timeout=timeout)
    except (Exception, asyncio.CancelledError):
        tr.close()
        raise

    con = connection_class(  # type: ignore[call-arg]
        pr, tr, loop, addr, config, params_input
    )
    pr.set_connection(con)
    return con


async def _connect(
    *,
    loop: typing.Optional[asyncio.AbstractEventLoop],
    timeout: float,
    connection_class: typing.Type[_Connection],
    record_class: typing.Type[_Record],
    **kwargs: typing.Any
) -> _Connection:
    if loop is None:
        loop = asyncio.get_event_loop()

    addrs, params, config = _parse_connect_arguments(timeout=timeout, **kwargs)

    last_error: typing.Optional[BaseException] = None
    addr = None
    for addr in addrs:
        before = time.monotonic()
        try:
            con = await _connect_addr(
                addr=addr,
                loop=loop,
                timeout=timeout,
                params=params,
                config=config,
                connection_class=connection_class,
                record_class=record_class,
            )
        except (OSError, asyncio.TimeoutError, ConnectionError) as ex:
            last_error = ex
        else:
            return con
        finally:
            timeout -= time.monotonic() - before

    assert last_error is not None
    raise last_error


async def _cancel(*, loop: asyncio.AbstractEventLoop,
                  addr: typing.Union[typing.Tuple[str, int], str],
                  params: _ConnectionParameters,
                  backend_pid: int, backend_secret: str) -> None:

    class CancelProto(asyncio.Protocol):

        def __init__(self) -> None:
            self.on_disconnect = _create_future(loop)

        def connection_lost(self, exc: typing.Optional[Exception]) -> None:
            if not self.on_disconnect.done():
                self.on_disconnect.set_result(True)

    if isinstance(addr, str):
        tr, pr = typing.cast(typing.Tuple[asyncio.WriteTransport, CancelProto],
                             await loop.create_unix_connection(CancelProto,
                                                               addr))
    else:
        if params.ssl:
            tr, pr = await _create_ssl_connection(
                CancelProto,
                *addr,
                loop=loop,
                ssl_context=params.ssl,
                ssl_is_advisory=params.ssl_is_advisory)
        else:
            tr, pr = typing.cast(
                typing.Tuple[asyncio.WriteTransport, CancelProto],
                await loop.create_connection(CancelProto, *addr))
            _set_nodelay(_get_socket(tr))

    # Pack a CancelRequest message
    msg = struct.pack('!llll', 16, 80877102, backend_pid, backend_secret)

    try:
        tr.write(msg)
        await pr.on_disconnect
    finally:
        tr.close()


def _get_socket(transport: asyncio.BaseTransport) -> typing.Any:
    sock = transport.get_extra_info('socket')
    if sock is None:
        # Shouldn't happen with any asyncio-complaint event loop.
        raise ConnectionError(
            'could not get the socket for transport {!r}'.format(transport))
    return sock


def _set_nodelay(sock: typing.Any) -> None:
    if not hasattr(socket, 'AF_UNIX') or sock.family != socket.AF_UNIX:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)


def _create_future(loop: typing.Optional[asyncio.AbstractEventLoop]) \
        -> 'asyncio.Future[typing.Any]':
    try:
        create_future = typing.cast(
            asyncio.AbstractEventLoop, loop
        ).create_future
    except AttributeError:
        return asyncio.Future(loop=loop)
    else:
        return create_future()
