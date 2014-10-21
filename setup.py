#!/usr/bin/env python

import setuptools

setuptools.setup(
        name = 'neutrontool',
        version = '0.1a',
        description = 'Neutron tools for tunning and cleanup',
        author = 'Miguel Angel Ajo Pelayo',
        author_email = 'majopela@redhat.com',
        url = 'https://github.com/mangelajo/neutrontool',
        packages = setuptools.find_packages(exclude = ['ez_setup']),
        include_package_data = True,
        zip_safe = False,
        entry_points = {
            'console_scripts': [
                'neutrontool = neutrontool.neutrontool:main'
            ]},
        test_suite = 'neutrontool.test.testcases'
        )


