#!/usr/bin/python

outfile = '''#!/usr/bin/env python
from tests import tests
'''

def add_binary(binary):
    global outfile
    outfile += """
def test_{0}():
    tests.make_test_function("{0}")()
""".format(binary)

arches = ['amd64', 'x86', 'armel', 'armhf', 'aarch64', 'ppc', 'ppc64', 'mips', 'mipsel']
tests = ['arrays', 'loops', 'division']
ctfs = ['amd64', 'x86', 'armhf', 'ppc', 'aarch64']

for arch in arches:
    for test in tests:
        add_binary('test_{}_{}'.format(test, arch))

for ctf in ctfs:
    add_binary('ctf_{}'.format(ctf))

open('test.py','w').write(outfile)
