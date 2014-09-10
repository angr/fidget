CC_AMD64 = x86_64-linux-gnu-gcc
CC_X86 = x86_64-linux-gnu-gcc -m32
CC_ARMEL = arm-linux-gnueabi-gcc
CC_ARMHF = arm-linux-gnueabihf-gcc
CC_PPC = powerpc-linux-gnu-gcc
CC_PPC64 = powerpc-linux-gnu-gcc -m64
CC_MIPS = mips-linux-gnu-gcc
CC_MIPSEL = mipsel-linux-gnu-gcc
CC_AARCH64 = aarch64-linux-gnu-gcc

all: test_arrays test_loops test_division ctf

test_arrays: test_arrays.c
	$(CC_AMD64) -o test_arrays_amd64 $<
	$(CC_X86) -o test_arrays_x86 $<
	$(CC_ARMEL) -o test_arrays_armel $<
	$(CC_ARMHF) -o test_arrays_armhf $<
	$(CC_PPC) -o test_arrays_ppc $<
	$(CC_PPC64) -o test_arrays_ppc64 $<
	$(CC_MIPS) -o test_arrays_mips $<
	$(CC_MIPSEL) -o test_arrays_mipsel $<
	$(CC_AARCH64) -o test_arrays_aarch64 $<

test_loops: test_loops.c
	$(CC_AMD64) -o test_loops_amd64 $<
	$(CC_X86) -o test_loops_x86 $<
	$(CC_ARMEL) -o test_loops_armel $<
	$(CC_ARMHF) -o test_loops_armhf $<
	$(CC_PPC) -o test_loops_ppc $<
	$(CC_PPC64) -o test_loops_ppc64 $<
	$(CC_MIPS) -o test_loops_mips $<
	$(CC_MIPSEL) -o test_loops_mipsel $<
	$(CC_AARCH64) -o test_loops_aarch64 $<

test_division: test_division.c
	$(CC_AMD64) -o test_division_amd64 $<
	$(CC_X86) -o test_division_x86 $<
	$(CC_ARMEL) -o test_division_armel $<
	$(CC_ARMHF) -o test_division_armhf $<
	$(CC_PPC) -o test_division_ppc $<
	$(CC_PPC64) -o test_division_ppc64 $<
	$(CC_MIPS) -o test_division_mips $<
	$(CC_MIPSEL) -o test_division_mipsel $<
	$(CC_AARCH64) -o test_division_aarch64 $<

ctf:
	wget http://shell-storm.org/repo/CTF/GITS-2013/Pwnable/Shiftd-100/shiftd-3a9c2a55e77d1467ee46dfb931170c737d24f310 -O ctf_amd64
	wget http://shell-storm.org/repo/CTF/CodeGate-2014-Juinor-Quals/nuclear/nuclear -O ctf_x86
	wget http://andrewdutcher.com/helium/trafman -O ctf_armhf
	wget http://andrewdutcher.com/helium/deepblue -O ctf_ppc
	wget http://shell-storm.org/repo/CTF/Hitcon-2014/ty/ty-b83f0d0edeb8cfad76d30eddc58da139 -O ctf_aarch64
	chmod +x ctf_amd64 ctf_x86 ctf_armhf ctf_ppc ctf_aarch64

tests:
	scripts/gen_tests.py

.PHONY: clean cleanout

clean: cleanout
	rm -f test_division_*
	rm -f test_arrays_*
	rm -f test_loops_*
	rm -f ctf_amd64 ctf_x86 ctf_armhf ctf_ppc ctf_aarch64
	rm -f *.pyc scripts/*.pyc ../*.pyc
	rm -rf db THIS_IS_NOT_KEY_JUST_PASSCODE

cleanout:
	rm -f *.out
