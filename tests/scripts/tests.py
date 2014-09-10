import os, time
import subprocess
import nose
from fidget import Fidget

CTF_WINNER = 'Haha totally pwned'
ARRAYS_OUTPUT = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ\n'
LOOPS_OUTPUT = '0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64 65 66 67 68 69 70 71 72 73 74 75 76 77 78 79 80 81 82 83 84 85 86 87 88 89 90 91 92 93 94 95 96 97 98 99 \n'
DIVISION_OUTPUT = '''3/4 = 0
9/2 = 4
4/2 = 2
10/0 = ''' 

from exploit_amd64   import main as tester_amd64,   always as always_amd64
from exploit_x86     import main as tester_x86,     always as always_x86
from exploit_arm     import main as tester_arm,     always as always_arm
from exploit_ppc     import main as tester_ppc,     always as always_ppc
from exploit_aarch64 import main as tester_aarch64, always as always_aarch64

def make_test_function(binary):
    ctf = 'ctf_' in binary
    if ctf:
        if 'ctf_amd64' in binary: tester = tester_amd64; always = always_amd64
        elif 'ctf_x86' in binary: tester = tester_x86; always = always_x86
        elif 'ctf_armhf' in binary: tester = tester_arm; always = always_arm
        elif 'ctf_ppc' in binary: tester = tester_ppc; always = always_ppc
        elif 'ctf_aarch64' in binary: tester = tester_aarch64; always = always_aarch64
        else: raise Exception("What even is this ctf binary?")

        winner = CTF_WINNER
    else:
        if 'test_arrays' in binary: expected = ARRAYS_OUTPUT
        elif 'test_loops' in binary: expected = LOOPS_OUTPUT
        elif 'test_division' in binary: expected = DIVISION_OUTPUT

    def out():
        if ctf:
            generic_ctf_test(binary, tester, always, winner)
        else:
            generic_test(binary, expected)

    return out



def generic_ctf_test(binary, tester, always, winner):
    nose.tools.assert_in(binary, os.listdir('tests'))

    os.chdir('tests')
    process = boot(binary)
    try:
        testdata = tester()
        testdata2 = tester()
    finally:
        process.kill()
        os.chdir('..')

    nose.tools.assert_in(always, testdata)
    nose.tools.assert_in(winner, testdata)
    nose.tools.assert_in(always, testdata2)
    nose.tools.assert_in(winner, testdata2)

    fidgetress = Fidget('tests/' + binary, verbose=-1)
    fidgetress.patch()
    nose.tools.assert_not_equals(len(fidgetress.dump_patches()), 0)
    fidgetress.apply_patches()

    nose.tools.assert_in(binary + '.out', os.listdir('tests'))

    os.chdir('tests')
    process = boot(binary + '.out')
    try:
        testdata = tester()
        testdata2 = tester()
    finally:
        process.kill()
        os.chdir('..')

    nose.tools.assert_in(always, testdata)
    nose.tools.assert_not_in(winner, testdata)
    nose.tools.assert_in(always, testdata2)
    nose.tools.assert_not_in(winner, testdata2)

def generic_test(binary, expected):
    nose.tools.assert_in(binary, os.listdir('tests'))

    os.chdir('tests')
    process = boot(binary)
    output = process.output()
    os.chdir('..')
    nose.tools.assert_in(expected, output)

    fidgetress = Fidget('tests/' + binary, verbose=-1)
    fidgetress.patch()
    nose.tools.assert_not_equals(len(fidgetress.dump_patches()), 0)
    fidgetress.apply_patches()

    nose.tools.assert_in(binary + '.out', os.listdir('tests'))

    os.chdir('tests')
    process = boot(binary + '.out')
    output = process.output()
    os.chdir('..')
    nose.tools.assert_in(expected, output)


def boot(binary):
    async = 'ctf_' in binary

    arch = ''

    for myname in arch_bullcrap:
        if myname in binary and len(myname) > len(arch):
            arch = myname
    if arch == '':
        raise Exception('Binary not suffixed properly!')

    socketserver = None
    if binary.startswith('ctf_amd64'):
        socketserver = 1098
    elif binary.startswith('ctf_ppc'):
        socketserver = 8888
    elif binary.startswith('ctf_armhf'):
        socketserver = 8000
    elif binary.startswith('ctf_aarch64'):
        socketserver = 4464

    return Process(binary='./' + binary, async=async, arch=arch, socketserver=socketserver)

arch_bullcrap = {
    'amd64': [],
    'x86': [],
    'ppc': ['qemu-ppc', '-L', '/usr/powerpc-linux-gnu', '-E', 'LD_LIBRARY_PATH=/usr/powerpc-linux-gnu/lib'],
    'ppc64': ['qemu-ppc64', '-L', '/usr/powerpc-linux-gnu', '-E', 'LD_LIBRARY_PATH=/usr/powerpc-linux-gnu/lib64'],
    'armel': ['qemu-arm', '-L', '/usr/arm-linux-gnueabi', '-E', 'LD_LIBRARY_PATH=/usr/arm-linux-gnueabi/lib'],
    'armhf': ['qemu-arm', '-L', '/usr/arm-linux-gnueabihf', '-E', 'LD_LIBRARY_PATH=/usr/arm-linux-gnueabihf/lib'],
    'aarch64': ['qemu-aarch64', '-L', '/usr/aarch64-linux-gnu', '-E', 'LD_LIBRARY_PATH=/usr/aarch64-linux-gnu/lib'],
    'mips': ['qemu-mips', '-L', '/usr/mips-linux-gnu', '-E', 'LD_LIBRARY_PATH=/usr/mips-linux-gnu/lib'],
    'mipsel': ['qemu-mipsel', '-L', '/usr/mipsel-linux-gnu', '-E', 'LD_LIBRARY_PATH=/usr/mipsel-linux-gnu/lib'],
        }

class Process:
    def __init__(self, binary, async, arch, socketserver):
        command = arch_bullcrap[arch] + [binary]
        if socketserver:
            command = ['scripts/serve-stdio', ' '.join(command), str(socketserver)]
        kwargs = {}
        if not async:
            kwargs['stdout'] = subprocess.PIPE
        #print command
        self.process = subprocess.Popen(command, **kwargs)
        if async:
            time.sleep(0.5)
        
    def output(self):
        return self.process.stdout.read()

    def kill(self):
        self.process.kill()
