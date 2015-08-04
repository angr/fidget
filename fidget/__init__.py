from .patching import Fidget
from .binary_data import BinaryData

def patch_file(infile, outfile, options):
    fidgetress = Fidget(infile, **options.pop('Fidget', {}))
    fidgetress.patch(**options)
    fidgetress.apply_patches(outfile)
