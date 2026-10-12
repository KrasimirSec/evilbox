#!/usr/bin/env python3
"""setuptools shim so pip < 21.3 can do an editable install without PEP 660."""

from setuptools import find_packages, setup

setup(
    name="evilbox",
    version="0.1.0",
    packages=find_packages(include=["evilbox", "evilbox.*"]),
    package_data={"evilbox": ["web_index.html"]},
    include_package_data=True,
    python_requires=">=3.10",
    install_requires=[
        "tree-sitter>=0.23",
        "tree-sitter-javascript>=0.23",
        "tree-sitter-php>=0.23",
        "jsbeautifier>=1.14",
    ],
    extras_require={"dev": ["pytest>=8", "hypothesis>=6"]},
    entry_points={"console_scripts": ["evilbox=evilbox.cli:main"]},
)
