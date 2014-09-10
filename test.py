#!/usr/bin/env python
import os, sys, traceback
sys.path.append('tests/scripts')
import tests

def setup_module():
    os.system('make -C tests')

def test_test_arrays_amd64():
    tests.make_test_function("test_arrays_amd64")()

def test_test_loops_amd64():
    tests.make_test_function("test_loops_amd64")()

def test_test_division_amd64():
    tests.make_test_function("test_division_amd64")()

def test_test_arrays_x86():
    tests.make_test_function("test_arrays_x86")()

def test_test_loops_x86():
    tests.make_test_function("test_loops_x86")()

def test_test_division_x86():
    tests.make_test_function("test_division_x86")()

def test_test_arrays_armel():
    tests.make_test_function("test_arrays_armel")()

def test_test_loops_armel():
    tests.make_test_function("test_loops_armel")()

def test_test_division_armel():
    tests.make_test_function("test_division_armel")()

def test_test_arrays_armhf():
    tests.make_test_function("test_arrays_armhf")()

def test_test_loops_armhf():
    tests.make_test_function("test_loops_armhf")()

def test_test_division_armhf():
    tests.make_test_function("test_division_armhf")()

def test_test_arrays_aarch64():
    tests.make_test_function("test_arrays_aarch64")()

def test_test_loops_aarch64():
    tests.make_test_function("test_loops_aarch64")()

def test_test_division_aarch64():
    tests.make_test_function("test_division_aarch64")()

def test_test_arrays_ppc():
    tests.make_test_function("test_arrays_ppc")()

def test_test_loops_ppc():
    tests.make_test_function("test_loops_ppc")()

def test_test_division_ppc():
    tests.make_test_function("test_division_ppc")()

def test_test_arrays_ppc64():
    tests.make_test_function("test_arrays_ppc64")()

def test_test_loops_ppc64():
    tests.make_test_function("test_loops_ppc64")()

def test_test_division_ppc64():
    tests.make_test_function("test_division_ppc64")()

def test_test_arrays_mips():
    tests.make_test_function("test_arrays_mips")()

def test_test_loops_mips():
    tests.make_test_function("test_loops_mips")()

def test_test_division_mips():
    tests.make_test_function("test_division_mips")()

def test_test_arrays_mipsel():
    tests.make_test_function("test_arrays_mipsel")()

def test_test_loops_mipsel():
    tests.make_test_function("test_loops_mipsel")()

def test_test_division_mipsel():
    tests.make_test_function("test_division_mipsel")()

def test_ctf_amd64():
    tests.make_test_function("ctf_amd64")()

def test_ctf_x86():
    tests.make_test_function("ctf_x86")()

def test_ctf_armhf():
    tests.make_test_function("ctf_armhf")()

def test_ctf_ppc():
    tests.make_test_function("ctf_ppc")()

def test_ctf_aarch64():
    tests.make_test_function("ctf_aarch64")()

funcs = [test_test_arrays_amd64, test_test_loops_amd64, test_test_division_amd64, test_test_arrays_x86, test_test_loops_x86, test_test_division_x86, test_test_arrays_armel, test_test_loops_armel, test_test_division_armel, test_test_arrays_armhf, test_test_loops_armhf, test_test_division_armhf, test_test_arrays_aarch64, test_test_loops_aarch64, test_test_division_aarch64, test_test_arrays_ppc, test_test_loops_ppc, test_test_division_ppc, test_test_arrays_ppc64, test_test_loops_ppc64, test_test_division_ppc64, test_test_arrays_mips, test_test_loops_mips, test_test_division_mips, test_test_arrays_mipsel, test_test_loops_mipsel, test_test_division_mipsel, test_ctf_amd64, test_ctf_x86, test_ctf_armhf, test_ctf_ppc, test_ctf_aarch64]

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

