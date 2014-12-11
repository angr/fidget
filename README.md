fidget
======

Fidget is a project to analyze an ELF, parse out its functions, and mess with 
the stack frame allocation and layout of each function such that any attack 
that makes assumptions about the stack layout will fail, which should protect 
against any exploit leveraging a buffer overflow or format string 
vulnerability, which is most of them.


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
ln -s $(pwd)/fidget $VIRTUAL_ENV/lib/python2.7/site-packages/fidget
ln -s $(pwd)/script/fidget $VIRTUAL_ENV/bin/fidget
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

Using as a Test Suite
---------------------

`test.py` in the project root is a nose testsuite that provides end-to-end tests for
the entire angr suite. If you actually run it with `nosetests`, you will probably want
to specify `-v --nocapture --nologcapture` for your own sanity.

It can also be run as an actual script, which will run all the tests and format the 
results similarly to nosetests. No comment on how long I spent getting this working.

All tests pass as far as I know. There are more test cases, but they are for unsupported
architectures (thumb and aarch64) and thus will not pass for a very long time.

Current caveats
---------------

- Will only work as well as angr can parse the control flow graph
- May break executables that use structs accessed with instance.field on the stack
- May break executables that use arrays accessed both in a loop and with instance[index]

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
through expanded stacks that it cannot handle an average data set.
