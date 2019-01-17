#!/usr/bin/env python
# -*- coding: utf-8 -*-
from setuptools import setup


setup(
    name='urlabuse',
    version='0.1',
    author='Raphaël Vinot',
    author_email='raphael.vinot@circl.lu',
    maintainer='Raphaël Vinot',
    url='https://github.com/CIRCL/url-abuse/',
    description='URL Abuse interface',
    packages=['urlabuse'],
    scripts=['bin/run_backend.py', 'bin/run_workers.py', 'bin/start.py', 'bin/start_website.py'],
    classifiers=[
        'License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)',
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Operating System :: POSIX :: Linux',
        'Intended Audience :: Science/Research',
        'Intended Audience :: Telecommunications Industry',
        'Intended Audience :: Information Technology',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
        'Topic :: Internet',
    ]
)
