# Copyright (C) 2016-present the asyncpg authors and contributors
# <see AUTHORS file>
#
# This module is part of asyncpg and is released under
# the Apache 2.0 License: http://www.apache.org/licenses/LICENSE-2.0

import os
import subprocess
import sys
import unittest


def find_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestCodeQuality(unittest.TestCase):

    def test_flake8(self):
        try:
            import flake8  # NoQA
        except ImportError:
            raise unittest.SkipTest('flake8 module is missing')

        root_path = find_root()
        config_path = os.path.join(root_path, '.flake8')
        if not os.path.exists(config_path):
            raise RuntimeError('could not locate .flake8 file')

        try:
            subprocess.run(
                [sys.executable, '-m', 'flake8', '--config', config_path],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=root_path)
        except subprocess.CalledProcessError as ex:
            output = ex.output.decode()
            raise AssertionError(
                'flake8 validation failed:\n{}'.format(output)) from None

    def test_mypy(self):
        try:
            import mypy  # NoQA
        except ImportError:
            raise unittest.SkipTest('mypy module is missing')

        root_path = find_root()
        config_path = os.path.join(root_path, 'mypy.ini')
        if not os.path.exists(config_path):
            raise RuntimeError('could not locate mypy.ini file')

        try:
            subprocess.run(
                [
                    sys.executable,
                    '-m',
                    'mypy',
                    '--config-file',
                    config_path,
                    'asyncpg'
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=root_path
            )
        except subprocess.CalledProcessError as ex:
            output = ex.output.decode()
            raise AssertionError(
                'mypy validation failed:\n{}'.format(output)) from None

    def test_mypy_plugin(self):
        try:
            import mypy  # NoQA
        except ImportError:
            raise unittest.SkipTest('mypy module is missing')

        root_path = find_root()
        config_path = os.path.join(root_path, 'mypy-plugin.ini')
        test_file_path = os.path.join(
            root_path, 'tests', 'typing', 'record.py'
        )
        if not os.path.exists(config_path):
            raise RuntimeError('could not locate mypy-plugin.ini file')

        output = None

        try:
            subprocess.run(
                [
                    sys.executable,
                    '-m',
                    'mypy',
                    '--config-file',
                    config_path,
                    test_file_path
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=root_path
            )
        except subprocess.CalledProcessError as ex:
            output = ex.output.decode()

        self.assertIsNotNone(output)
        self.assertEqual(
            list(map(lambda x: x.split(':', 1)[-1], output.splitlines())),
            [
                "32: note: Revealed type is 'Any'",
                "33: note: Revealed type is 'Any'",
                "35: error: Unsupported target for indexed assignment (\"A\")",
                "36: error: Record \"A\" has no index 0",
                "36: note: Revealed type is 'Any'",
                "37: error: Record \"A\" has no key 'foo'",
                "37: note: Revealed type is 'Any'",
                "39: error: Unsupported target for indexed assignment (\"B\")",
                "40: error: Unsupported target for indexed assignment (\"B\")",
                "42: note: Revealed type is 'builtins.str'",
                "43: note: Revealed type is 'builtins.str'",
                "44: error: Record \"B\" has no index 1",
                "44: note: Revealed type is 'Any'",
                "45: error: Record \"B\" has no key 'foo'",
                "45: note: Revealed type is 'Any'",
                "47: note: Revealed type is 'builtins.str'",
                "48: note: Revealed type is 'builtins.str'",
                "49: note: Revealed type is 'builtins.int'",
                "50: note: Revealed type is 'builtins.int'",
                "51: error: Record \"C\" has no index 2",
                "51: note: Revealed type is 'Any'",
                "52: error: Record \"C\" has no key 'foo'",
                "52: note: Revealed type is 'Any'",
                "54: note: Revealed type is 'Tuple[builtins.str, builtins.int, builtins.float]'",  # noqa
                "55: note: Revealed type is 'Tuple[builtins.str]'",
                "56: note: Revealed type is 'Tuple[builtins.float]'",
                "57: note: Revealed type is 'Tuple[builtins.int]'",
                "58: note: Revealed type is 'Tuple[]'",
                "Found 9 errors in 1 file (checked 1 source file)"
            ]
        )
