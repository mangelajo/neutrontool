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

neutrontool sg-rpc-mitigation-report

neutrontool sg-rpc-mitigation-script > sg_mitigation_script.sh

less sg_mitigation_script.sh 


## Dependencies

neutrontool depends on keystoneclient and neutronclient.

