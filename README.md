# Neutron tool

## What is neutrontool?

Neutrontool is a commandline tool to help in neutron maintenance. Mainly
focused in reporting and cleanup, as well as helping to workaround known
scale issues.

## How to use it

Download, and sudo python setup.py install

then run:

source ~/keystone_adminrc
neutrontool --help
neutrontool report

## Dependencies

neutrontool depends on keystoneclient and neutronclient.

