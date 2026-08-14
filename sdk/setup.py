# SPDX-License-Identifier: Apache-2.0
from setuptools import setup, find_packages

setup(
    name="securecollab",
    version="0.1.0",
    packages=find_packages(),
    install_requires=["requests", "tenseal", "cryptography>=42.0.0", "click>=8.1.0"],
    entry_points={"console_scripts": ["securecollab=securecollab.cli:main"]},
)
