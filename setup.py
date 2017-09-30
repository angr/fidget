#!/usr/bin/python

from distutils.core import setup

setup(name='Fidget',
      version='1.0',
      description='Binary mangling utility',
      author='rhelmot',
      packages=['fidget'],
      scripts=['script/fidget'],
      install_requires=[i.strip() for i in open('requirements.txt').readlines() if 'git' not in i]
)
