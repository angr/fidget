#!/usr/bin/env python
import os, sys, traceback
dd = os.path.dirname(__file__)
sd = os.path.realpath(os.path.join(dd, 'tests', 'scripts'))
sys.path.append(sd)
os.chdir(dd)
import tests

def setup_module():
    os.chdir(dd)
    os.system('make -C tests')

def test_test_arrays_amd64():
    os.chdir(dd)
    tests.make_test_function("test_arrays_amd64")()

def test_test_loops_amd64():
    os.chdir(dd)
    tests.make_test_function("test_loops_amd64")()

def test_test_division_amd64():
    os.chdir(dd)
    tests.make_test_function("test_division_amd64")()

def test_test_arrays_x86():
    os.chdir(dd)
    tests.make_test_function("test_arrays_x86")()

def test_test_loops_x86():
    os.chdir(dd)
    tests.make_test_function("test_loops_x86")()

def test_test_division_x86():
    os.chdir(dd)
    tests.make_test_function("test_division_x86")()

def test_test_arrays_armel():
    os.chdir(dd)
    tests.make_test_function("test_arrays_armel")()

def test_test_loops_armel():
    os.chdir(dd)
    tests.make_test_function("test_loops_armel")()

def test_test_division_armel():
    os.chdir(dd)
    tests.make_test_function("test_division_armel")()

def test_test_arrays_ppc():
    os.chdir(dd)
    tests.make_test_function("test_arrays_ppc")()

def test_test_loops_ppc():
    os.chdir(dd)
    tests.make_test_function("test_loops_ppc")()

def test_test_division_ppc():
    os.chdir(dd)
    tests.make_test_function("test_division_ppc")()

def test_test_arrays_ppc64():
    os.chdir(dd)
    tests.make_test_function("test_arrays_ppc64")()

def test_test_loops_ppc64():
    os.chdir(dd)
    tests.make_test_function("test_loops_ppc64")()

def test_test_division_ppc64():
    os.chdir(dd)
    tests.make_test_function("test_division_ppc64")()

def test_test_arrays_mips():
    os.chdir(dd)
    tests.make_test_function("test_arrays_mips")()

def test_test_loops_mips():
    os.chdir(dd)
    tests.make_test_function("test_loops_mips")()

def test_test_division_mips():
    os.chdir(dd)
    tests.make_test_function("test_division_mips")()

def test_test_arrays_mipsel():
    os.chdir(dd)
    tests.make_test_function("test_arrays_mipsel")()

def test_test_loops_mipsel():
    os.chdir(dd)
    tests.make_test_function("test_loops_mipsel")()

def test_test_division_mipsel():
    os.chdir(dd)
    tests.make_test_function("test_division_mipsel")()

def test_ctf_amd64():
    os.chdir(dd)
    tests.make_test_function("ctf_amd64")()

def test_ctf_x86():
    os.chdir(dd)
    tests.make_test_function("ctf_x86")()

def test_ctf_ppc():
    os.chdir(dd)
    tests.make_test_function("ctf_ppc")()

funcs = [test_test_arrays_amd64, test_test_loops_amd64, test_test_division_amd64, test_test_arrays_x86, test_test_loops_x86, test_test_division_x86, test_test_arrays_armel, test_test_loops_armel, test_test_division_armel, test_test_arrays_ppc, test_test_loops_ppc, test_test_division_ppc, test_test_arrays_ppc64, test_test_loops_ppc64, test_test_division_ppc64, test_test_arrays_mips, test_test_loops_mips, test_test_division_mips, test_test_arrays_mipsel, test_test_loops_mipsel, test_test_division_mipsel, test_ctf_amd64, test_ctf_x86, test_ctf_ppc]

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
            sys.stdout.write('FAIL\n')
            buf = traceback.format_exc()
            failures.append((func.func_name, buf))
        except Exception:
            sys.stdout.write('ERROR\n')
            buf = traceback.format_exc()
            errors.append((func.func_name, buf))
        except KeyboardInterrupt:
            sys.stdout.write('INTERRUPTED\n')
        else:
            sys.stdout.write('ok\n')
    for name, buf in failures:
        print '================================================'
        print '   FAILED: ' + name
        print '================================================'
        print buf
    print '\n'
    for name, buf in errors:
        print '================================================'
        print '   ERRORED: ' + name
        print '================================================'
        print buf

    print '\n'
    print 'Ran %d tests, %d failures, %d errors' % (len(funcs), len(failures), len(errors))

