import os
import subprocess
import time

import shellphish_qemu

from fidget import Fidget, FidgetDefaultTechnique

CTF_WINNER = b'Haha totally pwned'
ARRAYS_OUTPUT = b'ABCDEFGHIJKLMNOPQRSTUVWXYZ\n'
LOOPS_OUTPUT = b'0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64 65 66 67 68 69 70 71 72 73 74 75 76 77 78 79 80 81 82 83 84 85 86 87 88 89 90 91 92 93 94 95 96 97 98 99 \n'
DIVISION_OUTPUT = b'''3/4 = 0
9/2 = 4
4/2 = 2
10/0 = '''

from .exploit_amd64   import main as tester_amd64,   always as always_amd64
from .exploit_x86     import main as tester_x86,     always as always_x86
from .exploit_arm     import main as tester_arm,     always as always_arm
from .exploit_ppc     import main as tester_ppc,     always as always_ppc
from .exploit_aarch64 import main as tester_aarch64, always as always_aarch64

def test_single_binary(binary):
    ctf = 'ctf_' in binary
    if ctf:
        if   'x86_64'   in binary: tester = tester_amd64;   always = always_amd64
        elif 'i386'     in binary: tester = tester_x86;     always = always_x86
        elif 'armhf'    in binary: tester = tester_arm;     always = always_arm
        elif 'ppc'      in binary: tester = tester_ppc;     always = always_ppc
        elif 'aarch64'  in binary: tester = tester_aarch64; always = always_aarch64
        else: raise Exception("What even is this ctf binary?")
        winner = CTF_WINNER
    else:
        if   'test_arrays'   in binary: expected = ARRAYS_OUTPUT
        elif 'test_loops'    in binary: expected = LOOPS_OUTPUT
        elif 'test_division' in binary: expected = DIVISION_OUTPUT

    if ctf:
        generic_ctf_test(binary, tester, always, winner)
    else:
        generic_test(binary, expected)


def generic_ctf_test(binary, tester, always, winner):
    #process = boot(binary)
    #try:
    #    testdata = tester(binary)
    #finally:
    #    process.kill()

    #assert always in testdata
    #assert winner in testdata

    patched_binary = binary + '.out'

    fidgetress = Fidget(binary)
    fidgetress.patch(stacks={'technique': FidgetDefaultTechnique(), 'blacklist': ['_init']})
    assert len(fidgetress.dump_patches()) != 0
    fidgetress.apply_patches(patched_binary)

    process = boot(patched_binary)
    try:
        testdata = tester(patched_binary)
    finally:
        process.kill()
    os.unlink(patched_binary)

    assert always in testdata
    assert winner not in testdata

def generic_test(binary, expected):
    patched_binary = binary + '.out'

    process = boot(binary)
    output = process.output()
    assert expected in output

    fidgetress = Fidget(binary)
    fidgetress.patch(stacks={'technique': FidgetDefaultTechnique(), 'blacklist': ['_init']})
    assert len(fidgetress.dump_patches()) != 0
    fidgetress.apply_patches(patched_binary)

    process = boot(patched_binary)
    output = process.output()
    os.unlink(patched_binary)
    assert expected in output


def boot(binary):
    asynchronous = 'ctf_' in binary

    arch = ''

    for archname in qemu_name:
        if archname in binary and len(archname) > len(arch):
            arch = archname
    if arch == '':
        raise Exception('Binary not named properly!')

    socketserver = None
    if  'ctf_shifty' in binary:
        socketserver = 1098
    elif 'ctf_deepblue' in binary:
        socketserver = 8888
    elif 'ctf_armhf' in binary:
        socketserver = 8000
    elif 'ctf_aarch64' in binary:
        socketserver = 4464

    return Process(binary=binary, asynchronous=asynchronous, arch=arch, socketserver=socketserver)

qemu_name = {
    'x86_64': None,
    'i386': 'qemu-i386',
    'ppc': 'qemu-ppc',
    'ppc64': 'qemu-ppc64',
    'armel': 'qemu-arm',
    'armhf': 'qemu-arm',
    'aarch64': 'qemu-aarch64',
    'mips': 'qemu-mips',
    'mipsel': 'qemu-mipsel',
    'mips64': 'qemu-mips64'
}

qemu_path = {
    'x86_64': None,
    'i386': shellphish_qemu.qemu_path('i386'),
    'ppc': shellphish_qemu.qemu_path('ppc'),
    'ppc64': shellphish_qemu.qemu_path('ppc64'),
    'armel': shellphish_qemu.qemu_path('arm'),
    'armhf': shellphish_qemu.qemu_path('arm'),
    'aarch64': shellphish_qemu.qemu_path('aarch64'),
    'mips': shellphish_qemu.qemu_path('mips'),
    'mipsel': shellphish_qemu.qemu_path('mipsel'),
    'mips64': shellphish_qemu.qemu_path('mips64')
}

ld_name = {
    'x86_64': 'ld-linux-x86-64.so.2',
    'i386': 'ld-linux.so.2',
    'ppc': 'ld.so.1',
    'ppc64': 'ld64.so.1',
    'mips': 'ld.so.1',
    'mipsel': 'ld.so.1',
    'armel': 'ld-linux.so.3',
    'armhf': 'ld-linux-armhf.so.3',
    'mips64': 'ld.so.1',
    'aarch64': 'ld-linux-aarch64.so.1'
}

mydir = str(os.path.dirname(os.path.realpath(__file__)))

class Process:
    def __init__(self, binary, asynchronous, arch, socketserver):
        command = [os.path.join(os.path.dirname(binary), ld_name[arch]),
                '--library-path',
                os.path.dirname(binary),
                binary]
        if qemu_path[arch] is not None:
            command = [qemu_path[arch]] + command

        if socketserver:
            command = ['serve-stdio', str(socketserver)] + command
        kwargs = {'cwd': mydir}
        if not asynchronous:
            kwargs['stdout'] = subprocess.PIPE
        self.process = subprocess.Popen(command, **kwargs)
        if asynchronous:
            time.sleep(0.5)

    def output(self):
        return self.process.stdout.read()

    def kill(self):
        self.process.kill()
