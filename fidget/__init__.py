from patching import Fidget

def patch_file(infile, outfile, **options):
    fidgetress = Fidget(infile, **options)
    fidgetress.patch()
    fidgetress.apply_patches(outfile)
