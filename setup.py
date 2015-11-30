#!/usr/bin/env python

from setuptools import setup, find_packages
DESCRIPTION = ( "X.509v3 Certificate Validation built on cryptography.io" )
with open( 'README.rst' ) as f:
    LONG_DESCRIPTION = f.read()

install_requires = [
    'cryptograpy>=0.1.1'
]

setup( 
    name = 'Eve',
    version = '0.0.1.dev0',
    description = DESCRIPTION,
    long_description = DESCRIPTION,
    author = 'Rowland Smith',
    author_email = 'rowland@river2sea.org',
    url = 'https://github.com/river2sea/X509Validation',
    license = 'MIT',
    platforms = ["any"],
    packages = find_packages(),
    test_suite = "cryptographyx.ValidationTest.py",
    install_requires = install_requires,
    tests_require = [],
    classifiers = [
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Topic :: Cryptography :: X.509',
    ],
 )
