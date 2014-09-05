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

Current caveats
---------------

- Will only work as well as angr can parse the control flow graph
- May break executables that use structs accessed with instance.field on the stack
- May break executables that use arrays accessed both in a loop and with instance[index]


