#!/usr/bin/env python
import unittest

import os
import testinfo

testloc = str(os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests')))

arches = ['x86_64', 'i386', 'armel', 'armhf', 'aarch64', 'ppc', 'ppc64', 'mips', 'mipsel'] #, 'mips64']
ctf_binaries = ['x86_64/ctf_shifty', 'i386/ctf_nuclear', 'ppc/ctf_deepblue']

class TestFidget(unittest.TestCase):
    def test_arrays_x86_64(self):
        binary = os.path.join(testloc, 'x86_64', 'test_arrays')
        testinfo.test_single_binary(binary)

    def test_arrays_i386(self):
        binary = os.path.join(testloc, 'i386', 'test_arrays')
        testinfo.test_single_binary(binary)

    def test_arrays_armel(self):
        binary = os.path.join(testloc, 'armel', 'test_arrays')
        testinfo.test_single_binary(binary)

    def test_arrays_armhf(self):
        binary = os.path.join(testloc, 'armhf', 'test_arrays')
        testinfo.test_single_binary(binary)

    def test_arrays_aarch64(self):
        binary = os.path.join(testloc, 'aarch64', 'test_arrays')
        testinfo.test_single_binary(binary)

    def test_arrays_ppc(self):
        binary = os.path.join(testloc, 'ppc', 'test_arrays')
        testinfo.test_single_binary(binary)

    def test_arrays_ppc64(self):
        binary = os.path.join(testloc, 'ppc64', 'test_arrays')
        testinfo.test_single_binary(binary)

    def test_arrays_mips(self):
        binary = os.path.join(testloc, 'mips', 'test_arrays')
        testinfo.test_single_binary(binary)

    def test_arrays_mipsel(self):
        binary = os.path.join(testloc, 'mipsel', 'test_arrays')
        testinfo.test_single_binary(binary)

    def test_loops_x86_64(self):
        binary = os.path.join(testloc, 'x86_64', 'test_loops')
        testinfo.test_single_binary(binary)

    def test_loops_i386(self):
        binary = os.path.join(testloc, 'i386', 'test_loops')
        testinfo.test_single_binary(binary)

    def test_loops_armel(self):
        binary = os.path.join(testloc, 'armel', 'test_loops')
        testinfo.test_single_binary(binary)

    def test_loops_armhf(self):
        binary = os.path.join(testloc, 'armhf', 'test_loops')
        testinfo.test_single_binary(binary)

    def test_loops_aarch64(self):
        binary = os.path.join(testloc, 'aarch64', 'test_loops')
        testinfo.test_single_binary(binary)

    def test_loops_ppc(self):
        binary = os.path.join(testloc, 'ppc', 'test_loops')
        testinfo.test_single_binary(binary)

    def test_loops_ppc64(self):
        binary = os.path.join(testloc, 'ppc64', 'test_loops')
        testinfo.test_single_binary(binary)

    def test_loops_mips(self):
        binary = os.path.join(testloc, 'mips', 'test_loops')
        testinfo.test_single_binary(binary)

    def test_loops_mipsel(self):
        binary = os.path.join(testloc, 'mipsel', 'test_loops')
        testinfo.test_single_binary(binary)

    def test_division_x86_64(self):
        binary = os.path.join(testloc, 'x86_64', 'test_division')
        testinfo.test_single_binary(binary)

    def test_division_i386(self):
        binary = os.path.join(testloc, 'i386', 'test_division')
        testinfo.test_single_binary(binary)

    def test_division_armel(self):
        binary = os.path.join(testloc, 'armel', 'test_division')
        testinfo.test_single_binary(binary)

    def test_division_armhf(self):
        binary = os.path.join(testloc, 'armhf', 'test_division')
        testinfo.test_single_binary(binary)

    def test_division_aarch64(self):
        binary = os.path.join(testloc, 'aarch64', 'test_division')
        testinfo.test_single_binary(binary)

    def test_division_ppc(self):
        binary = os.path.join(testloc, 'ppc', 'test_division')
        testinfo.test_single_binary(binary)

    def test_division_ppc64(self):
        binary = os.path.join(testloc, 'ppc64', 'test_division')
        testinfo.test_single_binary(binary)

    def test_division_mips(self):
        binary = os.path.join(testloc, 'mips', 'test_division')
        testinfo.test_single_binary(binary)

    def test_division_mipsel(self):
        binary = os.path.join(testloc, 'mipsel', 'test_division')
        testinfo.test_single_binary(binary)

    def test_ctf_x86_64(self):
        binary = os.path.join(testloc, 'x86_64/ctf_shifty')
        testinfo.test_single_binary(binary)

    def test_ctf_i386(self):
        binary = os.path.join(testloc, 'i386/ctf_nuclear')
        testinfo.test_single_binary(binary)

    def test_ctf_ppc(self):
        binary = os.path.join(testloc, 'ppc/ctf_deepblue')
        testinfo.test_single_binary(binary)

if __name__ == '__main__':
    unittest.main()
