# flake8: noqa
import asyncpg

# NOTE: This file is not meant to be run and is only used to test
# the mypy plugin. The `reveal_type` function below is not an actual
# function and is only a mypy convention to output type information.


class A(asyncpg.Record):
    ...


class B(asyncpg.Record):
    name: str


class C(B):
    count: int


class D(C):
    timeout: float


def main(
    record: asyncpg.Record,
    record_a: A,
    record_b: B,
    record_c: C,
    record_d: D
) -> None:
    reveal_type(record[0])
    reveal_type(record['foo'])

    record_a[0] = 1
    reveal_type(record_a[0])
    reveal_type(record_a['foo'])

    record_b[0] = 1
    record_b['name'] = 1

    reveal_type(record_b[0])
    reveal_type(record_b['name'])
    reveal_type(record_b[1])
    reveal_type(record_b['foo'])

    reveal_type(record_c[0])
    reveal_type(record_c['name'])
    reveal_type(record_c[1])
    reveal_type(record_c['count'])
    reveal_type(record_c[2])
    reveal_type(record_c['foo'])

    reveal_type(record_d[:])
    reveal_type(record_d[:1])
    reveal_type(record_d[::-11])
    reveal_type(record_d[1:2])
    reveal_type(record_d[2:2])
