#!/usr/bin/env python

import os
from setuptools import setup
import twoping


def read(filename):
    return open(os.path.join(os.path.dirname(__file__), filename)).read()


setup(
    name='2ping',
    description='2ping a bi-directional ping utility',
    long_description=read('README'),
    version=twoping.__version__,
    license='GPLv2+',
    platforms=['Unix'],
    author='Ryan Finnie',
    author_email='ryan@finnie.org',
    url='http://www.finnie.org/software/2ping/',
    download_url='http://www.finnie.org/software/2ping/',
    packages=['twoping'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)',
        'Operating System :: POSIX',
        'Programming Language :: Python',
        'Topic :: Utilities',
    ],
    entry_points={
        'console_scripts': [
            '2ping = twoping.cli:main',
            '2ping6 = twoping.cli:main',
        ],
    },
)
