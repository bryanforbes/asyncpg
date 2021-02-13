# Copyright (C) 2016-present the asyncpg authors and contributors
# <see AUTHORS file>
#
# This module is part of asyncpg and is released under
# the Apache 2.0 License: http://www.apache.org/licenses/LICENSE-2.0


import asyncio
import pathlib
import platform
import sys
import typing

if sys.version_info >= (3, 8):
    from typing import (
        Final as Final,
        Literal as Literal,
        Protocol as Protocol,
        TypedDict as TypedDict
    )
else:
    from typing_extensions import (  # noqa: F401
        Final as Final,
        Literal as Literal,
        Protocol as Protocol,
        TypedDict as TypedDict
    )


_T = typing.TypeVar('_T')
PY_36: Final = sys.version_info >= (3, 6)
PY_37: Final = sys.version_info >= (3, 7)
SYSTEM: Final = platform.uname().system


if sys.platform == 'win32':
    import ctypes.wintypes

    CSIDL_APPDATA = 0x001a

    def get_pg_home_directory() -> typing.Optional[pathlib.Path]:
        # We cannot simply use expanduser() as that returns the user's
        # home directory, whereas Postgres stores its config in
        # %AppData% on Windows.
        buf = ctypes.create_unicode_buffer(ctypes.wintypes.MAX_PATH)
        r = ctypes.windll.shell32.SHGetFolderPathW(0, CSIDL_APPDATA, 0, 0, buf)
        if r:
            return None
        else:
            return pathlib.Path(buf.value) / 'postgresql'
else:
    def get_pg_home_directory() -> typing.Optional[pathlib.Path]:
        return pathlib.Path.home()


if sys.version_info >= (3, 7):
    def current_asyncio_task(
        loop: typing.Optional[asyncio.AbstractEventLoop]
    ) -> typing.Optional['asyncio.Task[typing.Any]']:
        return asyncio.current_task(loop)
else:
    def current_asyncio_task(
        loop: typing.Optional[asyncio.AbstractEventLoop]
    ) -> typing.Optional['asyncio.Task[typing.Any]']:
        return asyncio.Task.current_task(loop)


async def wait_closed(stream: asyncio.StreamWriter) -> None:
    # Not all asyncio versions have StreamWriter.wait_closed().
    if hasattr(stream, 'wait_closed'):
        try:
            await typing.cast(typing.Any, stream).wait_closed()
        except ConnectionResetError:
            # On Windows wait_closed() sometimes propagates
            # ConnectionResetError which is totally unnecessary.
            pass


# Workaround for https://bugs.python.org/issue37658
async def wait_for(fut: 'asyncio.Future[_T]', timeout: float) -> _T:
    if timeout is None:
        return await fut

    fut = asyncio.ensure_future(fut)

    try:
        return await asyncio.wait_for(fut, timeout)
    except asyncio.CancelledError:
        if fut.done():
            return fut.result()
        else:
            raise
