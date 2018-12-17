#!/usr/bin/python
# -*- coding: utf-8 -*-
from setuptools import setup

setup(
    name='pyurlabuse',
    version='1.0',
    author='Raphaël Vinot',
    author_email='raphael.vinot@circl.lu',
    maintainer='Raphaël Vinot',
    url='https://github.com/CIRCL/url-abuse',
    description='Python API for URL Abuse.',
    long_description=open('README.md').read(),
    packages=['pyurlabuse'],
    classifiers=[
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: Science/Research',
        'Intended Audience :: Telecommunications Industry',
        'Programming Language :: Python',
        'Topic :: Security',
        'Topic :: Internet',
    ],
    install_requires=['requests'],
)
