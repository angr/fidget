#!/usr/bin/python

import os, sys

try:
    port = int(sys.argv[1])
    filename = sys.argv[2]
    with open(filename) as x: pass
except:
    print 'Usage: %s [port] [binary]'
    sys.exit(0)

os.system("socat -lm -d -d TCP-LISTEN:%d,fork EXEC:./%s" % (port, filename))
