#!/usr/bin/env python

import socket as pysocket
import sys, select, os

class NetcatError(Exception):
    pass

class Netcat:
    def __init__(self, server=None, sock=None, listen=None, verbose=0, dohex=False):
        if sock is None:
            self.dohex = dohex
            self.sock = pysocket.socket()
            if server is not None:
                self.sock.connect(server)
            elif listen is not None:
                self.sock.setsockopt(pysocket.SOL_SOCKET, pysocket.SO_REUSEADDR, 1)
                self.sock.bind(listen)
                self.sock.listen(1)
                conn, addr = self.sock.accept()
                self.sock.close()
                self.sock = conn
                self.server = addr
                if verbose:
                    print 'Connection from %s accepted' % str(addr)
            else:
                raise ValueError('Not enough arguments, need at least a server or a socket or a listening address!')
        else:
            self.sock = sock
        self.buf = ''
        self.verbose = verbose
        self.echo_headers = True
        self.echo_perline = True
        self.echo_sending = True
        self.echo_recving = True

    def head_buf(self, index):
        ret = self.buf[:index]
        self.buf = self.buf[index:]
        return ret

    def fileno(self):
        return self.sock.fileno()

    def recv(self, n=4096):
        if self.verbose and self.echo_headers:
            print '======== Receiving ({0}) ========'.format(n)
        if self.buf != '':
            ret = self.buf
            self.buf = ''
            if self.verbose and self.echo_recving:
                if self.dohex:
                    print ret.encode('hex')
                elif self.echo_perline:
                    print_lines(ret, '<< ')
                else:
                    print '<<', ret
            return ret
        
        try:
            ret = self.sock.recv(n)
        except pysocket.error:
            raise NetcatError('Socket error!')

        if ret == '':
            raise NetcatError("Connection dropped!")

        if self.verbose and self.echo_recving:
            if self.dohex:
                print ret.encode('hex')
            elif self.echo_perline:
                print_lines(ret, '<< ')
            else:
                print '<<', ret
        return ret

    def recv_until(self, s):
        if self.verbose and self.echo_headers:
            print '======== Receiving (until {0}) ========'.format(repr(s))
        while s not in self.buf:
            a = self.sock.recv(4096)
            if a == '':
                raise NetcatError("Connection dropped!")
            self.buf += a

        ret = self.head_buf(self.buf.index(s)+len(s))
        if self.verbose and self.echo_recving:
            if self.dohex:
                print ret.encode('hex')
            elif self.echo_perline:
                print_lines(ret, '<< ')
            else:
                print '<<', ret
        return ret

    def send(self, s):
        if self.verbose and self.echo_headers:
            print '======== Sending ({0}) ========'.format(len(s))

        if self.verbose and self.echo_sending:
            if self.dohex:
                print s.encode('hex')
            elif self.echo_perline:
                print_lines(s, '>> ')
            else:
                print '>>', s

        self.sock.send(s)

    read = recv
    read_until = recv_until
    write = send

    def interact(self, insock=sys.stdin, outsock=sys.stdout):
        try:
            dropped = False
            while not dropped:
                r, _, _ = select.select([self.sock, insock], [], [])
                for s in r:
                    if s == self.sock:
                        a = self.sock.recv(4096)
                        if a == '':
                            dropped = True
                            print '======== Connection dropped! ========'
                        else:
                            outsock.write(a)
                            outsock.flush()
                    else:
                        b = os.read(insock.fileno(), 4096)
                        self.sock.send(b)
        except KeyboardInterrupt:
            print '======== Connection interrupted! ========'
        except pysocket.error:
            print '======== Connection dropped! ========'

socket = Netcat

def create_connection(*args):
    return Netcat(sock=pysocket.create_connection(*args))

def print_lines(s, prefix):
    for line in s.split('\n'):
        print prefix + line

def add_arg(arg, options, args):
    if arg in ('v',):
        options['verbose'] += 1
    elif arg in ('l',):
        options['listen'] = True
    elif arg in ('k',):
        options['listenmore'] = True
    else:
        raise NetcatError('Bad argument: %s' % arg)

def usage(verbose=False):
    print """Usage: %s [-vlk] hostname port""" % sys.argv[0]
    if verbose:
        print """More help coming soon :)"""

def main(*args_list):
    args = iter(args_list)
    myname = args.next()
    hostname = None
    port = None
    options = {'verbose': False, 'listen': False, 'listenmore': False}
    for arg in args:
        if arg.startswith('--'):
            add_arg(arg, options, args)
        elif arg.startswith('-'):
            for argchar in arg[1:]:
                add_arg(argchar, options, args)
        else:
            if arg.isdigit():
                if port is not None:
                    if hostname is not None:
                        usage()
                        raise NetcatError('Already specified hostname and port: %s' % arg)
                    hostname = port # on the off chance the host is totally numeric :P
                port = int(arg)
            else:
                if hostname is not None:
                    usage()
                    raise NetcatError('Already specified hostname: %s' % arg)
                hostname = arg
    if port is None:
        usage()
        raise NetcatError('No port specified!')
    if options['listen']:
        hostname = '0.0.0.0' if hostname is None else hostname
        while True:
            Netcat(listen=(hostname, port), verbose=options['verbose']).interact()
            if not options['listenmore']:
                break
    else:
        if hostname is None:
            usage()
            raise NetcatError('No hostname specified!')
        Netcat(server=(hostname, port), verbose=options['verbose']).interact()


if __name__ == '__main__':
    main(*sys.argv)
