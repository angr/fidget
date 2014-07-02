def binary_patch(infile, patchdata, outfile=None):
    if outfile is None:
        outfile = infile + '.out'
    fin = open(infile)
    fout = open(outfile, 'w')
    s = 'a'
    while s != '':
        s = fin.read(1024*32)
        fout.write(s)
    for offset, data in patchdata:
        fout.seek(offset)
        fout.write(data)
    fin.close()
    fout.close()
