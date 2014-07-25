#!/usr/bin/python

import os, sys

try:
    port = int(sys.argv[2])
    filename = sys.argv[1]
    with open(filename) as x: pass
except:
    print 'Usage: %s [binary] [port]' % sys.argv[0]
    sys.exit(0)

os.system("socat TCP-LISTEN:%d,reuseaddr,fork EXEC:./%s" % (port, filename))
