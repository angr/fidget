#!/usr/bin/python

outfile = '''#!/usr/bin/env python
import os, sys, traceback
dd = os.path.dirname(__file__)
sd = os.path.realpath(os.path.join(dd, 'tests', 'scripts'))
sys.path.append(sd)
os.chdir(dd)
import tests

def setup_module():
    os.chdir(dd)
    os.system('make -C tests')
'''

funcs = []

kicker = '''
funcs = {0}

if __name__ == '__main__':
    setup_module()
    failures = []
    errors = []
    for func in funcs:
        sys.stdout.write('Running %s... ' % func.func_name)
        sys.stdout.flush()
        try:
            func()
        except AssertionError:
            sys.stdout.write('FAIL\\n')
            buf = traceback.format_exc()
            failures.append((func.func_name, buf))
        except Exception:
            sys.stdout.write('ERROR\\n')
            buf = traceback.format_exc()
            errors.append((func.func_name, buf))
        except KeyboardInterrupt:
            sys.stdout.write('INTERRUPTED\\n')
        else:
            sys.stdout.write('ok\\n')
    for name, buf in failures:
        print '================================================'
        print '   FAILED: ' + name
        print '================================================'
        print buf
    print '\\n'
    for name, buf in errors:
        print '================================================'
        print '   ERRORED: ' + name
        print '================================================'
        print buf

    print '\\n'
    print 'Ran %d tests, %d failures, %d errors' % (len(funcs), len(failures), len(errors))

'''

def add_binary(binary):
    global outfile, kicker
    outfile += """
def test_{0}():
    os.chdir(dd)
    tests.make_test_function("{0}")()
""".format(binary)

    funcs.append('test_' + binary)

arches = ['amd64', 'x86', 'armel', 'ppc', 'ppc64', 'mips', 'mipsel']
tests = ['arrays', 'loops', 'division']
ctfs = ['amd64', 'x86', 'ppc']

for arch in arches:
    for test in tests:
        add_binary('test_{}_{}'.format(test, arch))

for ctf in ctfs:
    add_binary('ctf_{}'.format(ctf))

open('test.py','w').write(outfile + kicker.format('[' + ', '.join(funcs) + ']'))
