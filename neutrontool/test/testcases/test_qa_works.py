# -*- mode: python; coding: utf-8 -*-

__author__ = "Miguel Angel Ajo Pelayo"
__email__ = "majopela@redhat.com"
__copyright__ = "Copyright (C) 2014 Miguel Angel Ajo Pelayo"
__license__ = "Apache License v2.0"

import neutrontool.test

class TestQAWorks(neutrontool.test.TestCase):

    def setUp(self):
        self.dummy = None

    def test_assert_true( self ):
        self.assertTrue( True )

    def test_assert_equal( self ):
        self.assertEqual(2, 1+1)


if __name__ == '__main__':
    unittest.main()
