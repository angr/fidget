import subprocess

CTF_WINNER = 'Haha totally pwned'
ARRAYS_OUTPUT = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ\n'
LOOPS_OUTPUT = '0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64 65 66 67 68 69 70 71 72 73 74 75 76 77 78 79 80 81 82 83 84 85 86 87 88 89 90 91 92 93 94 95 96 97 98 99 \n'
DIVISION_OUTPUT = '''3/4 = 0
9/2 = 4
4/2 = 2
10/0 = Error!
''' 

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
        elif 'ctf_arm' in binary: tester = tester_arm; always = always_arm
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
            test_generic_ctf(binary, tester, always, winner)
        else:
            test_generic(binary, expected)

    return out



def test_generic_ctf(binary, tester, always, winner):
    process = boot(binary)
    assert always in tester()
    assert winner in tester()
    process.kill()

    process = boot(binary + '.out')
    assert always in tester()
    assert winner not in tester()
    process.kill()

def test_generic(binary, expected):
    process = boot(binary)
    assert process.output() == expected

    process = boot(binary + '.out')
    assert process.output() == expected


def boot(binary):
    async = 'ctf_' in binary

    qemus = [('amd64', 'x86_64'), ('x86', 'i386'), ('ppc', 'ppc'), ('ppc64', 'ppc64'), ('arm', 'arm'), ('mips', 'mips'), ('aarch64', 'aarch64')]
    for myname, qemuname in qemus:
        if binary.endswith(myname):
            qemu = qemuname
            break
    else:
        raise Exception('Binary not suffixed properly!')

    socketserver = 1098 if binary.startswith('ctf_amd64') else None

    return Process(binary=binary, async=async, qemu=qemu, socketserver=socketserver)

class Process:
    def __init__(self, binary, async, qemu, socketserver):
        command = [qemu, binary]
        if socketserver:
            command = ['serve-stdio', qemu + ' ' + binary, str(socketserver)]
        kwargs = {}
        if not async:
            kwargs['stdout'] = subprocess.PIPE
        self.process = subprocess.Popen(command, **kwargs)
        
    def output(self):
        return self.process.stdout.read()

    def kill(self):
        self.process.kill()
