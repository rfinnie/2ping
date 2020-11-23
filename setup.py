#!/usr/bin/env python3

import os
import sys

from setuptools import setup


__version__ = "4.5"
assert sys.version_info > (3, 5)


def read(filename):
    with open(os.path.join(os.path.dirname(__file__), filename), encoding="utf-8") as f:
        return f.read()


setup(
    name="2ping",
    description="2ping a bi-directional ping utility",
    long_description=read("README.md"),
    long_description_content_type="text/markdown",
    version=__version__,
    license="GPLv2+",
    platforms=["Unix"],
    author="Ryan Finnie",
    author_email="ryan@finnie.org",
    url="https://www.finnie.org/software/2ping/",
    download_url="https://www.finnie.org/software/2ping/",
    packages=["twoping"],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)",
        "Natural Language :: English",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX",
        "Operating System :: Unix",
        "Programming Language :: Python :: 3 :: Only",
        "Topic :: Internet",
        "Topic :: System :: Networking",
        "Topic :: Utilities",
    ],
    entry_points={
        "console_scripts": ["2ping = twoping.cli:main", "2ping6 = twoping.cli:main"]
    },
)
