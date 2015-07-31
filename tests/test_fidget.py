#!/usr/bin/env python

import os
import testinfo

testloc = str(os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests')))

arches = ['x86_64', 'i386', 'armel', 'armhf', 'aarch64', 'ppc', 'ppc64', 'mips', 'mipsel', 'mips64']
ctf_binaries = ['x86_64/ctf_shifty', 'i386/ctf_nuclear', 'ppc/ctf_deepblue']

def test_arrays():
    for path in arches:
        binary = os.path.join(testloc, path, 'test_arrays')
        yield testinfo.test_single_binary, binary

def test_loops():
    for path in arches:
        binary = os.path.join(testloc, path, 'test_loops')
        yield testinfo.test_single_binary, binary

def test_division():
    for path in arches:
        binary = os.path.join(testloc, path, 'test_division')
        yield testinfo.test_single_binary, binary

def test_ctf():
    for path in ctf_binaries:
        binary = os.path.join(testloc, path)
        yield testinfo.test_single_binary, binary

if __name__ == '__main__':
    for testiter in (test_arrays(), test_loops(), test_division(), test_ctf()):
        for testfunc in testiter:
            testfunc[0](testfunc[1])
