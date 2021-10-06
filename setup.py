# -*- coding: utf-8 -*-

# Copyright 2020 Canonical Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Module used to setup the framework."""

from __future__ import print_function

from setuptools import setup, find_packages

version = "0.0.1"

install_requires = [
    # NOTE(aznashwan, 11/Oct/21): the current Pypi version of the `ops` package
    # is at 1.2 and lacks `container.can_connect()` and other such amenities,
    # so we skip declaring it here and reference the GitHub URL in req.txt
    # "ops",
    "pyjks",
    "pyOpenSSL"
]
tests_require = [
    'tox >= 2.3.1',
]

setup(
    license='Apache-2.0: http://www.apache.org/licenses/LICENSE-2.0',
    packages=find_packages(exclude=["unit_tests"]),
    zip_safe=False,
    install_requires=install_requires)
