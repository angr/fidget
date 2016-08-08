fidget
======

Fidget is a project to analyze a program, parse out its functions, and mess with 
the stack frame allocation and layout of each function such that any attack 
that makes assumptions about the stack layout will fail, which should protect 
against any exploit leveraging a stack buffer overflow or format string 
vulnerability, which is most of them.

Fidget works by attempting to classify stack memory accesses into variables
(very conservatively), describing this classification with SMT constraints,
and then tossing the whole mess into z3 and saying "give me another solution to this".

Installing
----------

```bash
workon angr
python setup.py install
```

This will copy the python library into your virtualenv's site-packages directory, 
and copy a small python script into your virtualenv's bin directory. If you want to 
do these as symlinks instead of copying (i.e. if you are in a dev environment), do 
the following:

```bash
workon angr
python setup.py develop
```

Using as a Script
-----------------

```bash
fidget <arguments>
```

Run it with no arguments for usage information.

Using it as a Library
---------------------

```python
from fidget import Fidget
fidgetress = Fidget(filepath, **options)
# Options can be none, read the docstring for details
fidgetress.patch()
fidgetress.apply_patches(output_file)
```

Using it as a Patching Utility
------------------------------

Fidget has a lot of code dedicated to finding the exact way to change instruction bytes
in order to change immediate values in the instruction. If you'd like to programatically
do exactly this, fidget exposes this interface for you!

This sample code should change the immediate value `value` present in the instruction at
address `addr` to the new value `new_value`.

```python
import angr
from fidget import BinaryData

project = angr.Project(my_binary)
bd = BinaryData(project, addr, value)
patch_data = bd.get_patch_data(new_value)

with open(my_binary, 'r+') as f:
    for phys_patch_addr, patch_bytes in patch_data:
        f.seek(phys_patch_addr)
		f.write(patch_bytes)
```

If there are more than one of the same immediate in a single instruction (???) you can
specify the `skip` keyword argument in order to skip a given number of the immediate.

If for any reason your request can't be accomidated, a `fidget.errors.ValueNotFoundError`
will be thrown. This is either because you're trying to change an immediate not actually
represented in an instruction (e.g. the stack shift amount in a push or pop instruction)
or you're trying to insert an immediate that cannot be represented by the instruction.

Using it as a Test Suite
---------------------

`tests/test_fidget.py` is a nose testsuite that provides end-to-end tests for
the entire angr suite. If you actually run it with `nosetests`, you will probably want
to specify `-v --nocapture --nologcapture` for your own sanity. You need to have the
angr test binaries cloned if you want this to work.

It can also be run as an actual script, which will run all the tests and format the 
results similarly to nosetests. No comment on how long I spent getting this working.

All tests pass; they're run on pretty much every commit to the angr internal git setup.
They're very good at catching weird bugs deep in claripy!

Current caveats
---------------

- May break executables that use structs on the stack accessed with instance.field
- May break executables that use arrays accessed both in a loop and with instance[index]

The above caveats are fixable by using fidget in safe mode, e.g. the `--safe` flag. The
below caveats are much more sinister.

- Will only work as well as angr can parse the control flow graph
- The fundemental patching analysis has a flaw where if the same immediate value is used
  both as an offset to an array and as some other semantic value, like a loop limit.
  This is a very scary, very fundemental bug, and is the reason that fidget was pulled
  from Shellphish's CGC entry. Strangely enough, this bug never manifested until two years
  into fidget's life, despite the codebase having been relatively stable for the last year
  and a half, so it's very possible that this is just a simple bug that was introduce by a
  silly half-awake change I made recently.

The Future
----------

Fidget will be greatly improved when it learns to use Angr's VFG and variable detection
capacities. Greatly, greatly improved. Like so improved. So improved you should be afraid.
It will come in the night. Rearrange your binaries. You won't notice it at first, but when
you do, it will eat away at your psyche and you will eventually go insane. Nobody will
believe you. Your own binaries? Being rearranged without altering their functionality?
Unheard of. So your stack frames are putting on some weight. Nothing to be ashamed of.
But still. They grow larger and larger. One night you awaken in a cold sweat to the sound
of a segfault. Looking around wildly you see that your stack has overflown. What should
have been a simple O(n log n) recursive algorithm has gained such a huge constant factor
through expanded stacks that it cannot handle an average data set. You are forever ruined.

Truthfully, I wrote the previous passage when I was debugging the angr internal CI and
needed to push something in order to trigger a build, several times in a row. But actually,
since then I implemented something called a fidget technique that lets you specify how to
identify and rearrange the variables. Most of fidget's analysis is to understand how to
change bits in the program in order to change where values are stored in memory, and sort
of hacked on top of this are some access pattern heuristics that conservatively clump
memory accesses into variables and say "well ok what if we tried putting some space
in between them? is that good enough?" and the answer is usually "no, binary analysis
is hard and you should be ashamed of yourself for having the hubris to legitimately
think that a silly hack like this would a) actually fucking work reliably and b) actually
fucking prevent real attacks from working"

anyway

Theoretically you can now plug any source of variable identification and any rearrangement
strategy into fidget by writing a FidgetTechnique (`fidget/techniques.py`) to specify these
behaviors. You have to interact with some pretty meaty fidget internals in order to do this
though, so you should probably just study the existing ones.

As a final note, `fidget/new_analysis.py` contains a new, experimental, *nonfunctional* analysis
to perform abstract interpretation with modern angr components to classify every memory access
in the program by which structure it belongs to, the eventual goal being to be able to perform
fidget's rewriting on generic structures, independant from any one stack layout. Pretty rad!
It doesn't work at all. Please don't try to use this code for anything except learning how to
perform abstract interpretation with angr (ngl this is a pretty janky implementation compared
to e.g. the VSA stuff), or maybe if you just want to read more code I've written, for some reason.
