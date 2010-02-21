# Copyright (C) Frederick Dean 2009, All rights reserved

"""
Unit tests for L{OpenSSL.rand}.
"""

from unittest import main
import os 
import stat

from OpenSSL.test.util import TestCase
from OpenSSL import rand


class RandTests(TestCase):
    def test_bytes(self):
        """
        Verify that we can obtain bytes from rand_bytes() and
        that they are different each time.  Test the parameter
        of rand_bytes() for bad values.
        """
        b1 = rand.bytes(50)
        self.assertEqual(len(b1), 50)
        b2 = rand.bytes(num_bytes=50)  # parameter by name
        self.assertNotEqual(b1, b2)  #  Hip, Hip, Horay! FIPS complaince
        b3 = rand.bytes(num_bytes=0) 
        self.assertEqual(len(b3), 0)
        exc = self.assertRaises(ValueError, rand.bytes, -1)
        self.assertEqual(str(exc), "num_bytes must not be negative")


    def test_add(self):
        """
        L{OpenSSL.rand.add} adds entropy to the PRNG.
        """
        rand.add('hamburger', 3)


    def test_seed(self):
        """
        L{OpenSSL.rand.seed} adds entropy to the PRNG.
        """
        rand.seed('milk shake')


    def test_status(self):
        """
        L{OpenSSL.rand.status} returns C{True} if the PRNG has sufficient
        entropy, C{False} otherwise.
        """
        # It's hard to know what it is actually going to return.  Different
        # OpenSSL random engines decide differently whether they have enough
        # entropy or not.
        self.assertTrue(rand.status() in (1, 2))


    def test_files(self):
        """
        Test reading and writing of files via rand functions.
        """
        # Write random bytes to a file 
        tmpfile = self.mktemp()
        # Make sure it exists (so cleanup definitely succeeds)
        fObj = file(tmpfile, 'w')
        fObj.close()
        try:
            rand.write_file(tmpfile)
            # Verify length of written file
            size = os.stat(tmpfile)[stat.ST_SIZE]
            self.assertEquals(size, 1024)
            # Read random bytes from file 
            rand.load_file(tmpfile)
            rand.load_file(tmpfile, 4)  # specify a length
        finally:
            # Cleanup
            os.unlink(tmpfile)


if __name__ == '__main__':
    main()
