#!/usr/bin/env python

import os
from setuptools import setup


def read(filename):
    return open(os.path.join(os.path.dirname(__file__), filename)).read()


setup(
    name='2ping',
    description='2ping a bi-directional ping utility',
    long_description=read('README'),
    version='3.2.1',
    license='GPLv2+',
    platforms=['Unix'],
    author='Ryan Finnie',
    author_email='ryan@finnie.org',
    url='http://www.finnie.org/software/2ping/',
    download_url='http://www.finnie.org/software/2ping/',
    packages=['twoping'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)',
        'Natural Language :: English',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX',
        'Operating System :: Unix',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Topic :: Internet',
        'Topic :: System :: Networking',
        'Topic :: Utilities',
    ],
    entry_points={
        'console_scripts': [
            '2ping = twoping.cli:main',
            '2ping6 = twoping.cli:main',
        ],
    },
    test_suite='tests',
)
