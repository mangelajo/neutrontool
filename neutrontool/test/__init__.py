# -*- mode: python; coding: utf-8 -*-

__author__ = "Miguel Angel Ajo Pelayo"
__email__ = "majopela@redhat.com"
__copyright__ = "Copyright (C) 2014 Miguel Angel Ajo Pelayo"
__license__ = "Apache License, Version 2.0"

import unittest
import os.path
import platform

if platform.python_version() < '2.7':
    unittest = __import__('unittest2')
else:
    import unittest

class TestCase(unittest.TestCase):
    def get_data_path(self,file_path):
        return os.path.join(os.path.dirname(__file__),'data',file_path)
