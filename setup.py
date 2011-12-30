#!/usr/bin/env python

from distutils.core import setup

setup(name='Signedauth',
      version='1.1',
      description='Simple signing of urls for use by APIs',
      author='Bruce Kroeze',
      author_email='bruce@ecomsmith.com',
      url='https://github.com/bkroeze/django-signedauth',
      packages=['signedauth',],
      install_requires=[
        'django-keyedcache >= 1.4',
        'httplib2 >= 0.7.2',
        ]
     )
