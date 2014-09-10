import socket as pysocket
import os, sys

class NetcatError(Exception):
    pass

class Netcat:
    def __init__(self, server=None):
        self.sock = pysocket.socket()
        if server is not None:
            self.sock.connect(server)
        self.buf = ''
        self.echo = False
        self.echo_headers = True
        self.echo_perline = True
        self.echo_sending = True
        self.echo_recving = True

    def head_buf(self, index):
        ret = self.buf[:index]
        self.buf = self.buf[index:]
        return ret

    def recv(self, n=4096):
        if self.echo and self.echo_headers:
            print '======== Receiving ({0}) ========'.format(n)
        if self.buf != '':
            ret = self.buf
            self.buf = ''
            if self.echo and self.echo_recving:
                if self.echo_perline:
                    print_lines(ret, '<< ')
                else:
                    print '<<', ret
            return ret

        ret = self.sock.recv(n)
        if ret == '':
            raise NetcatError("Connection dropped!")

        if self.echo and self.echo_recving:
            if self.echo_perline:
                print_lines(ret, '<< ')
            else:
                print '<<', ret
        return ret

    def recv_until(self, s):
        if self.echo and self.echo_headers:
            print '======== Receiving (until {0}) ========'.format(repr(s))
        while s not in self.buf:
            a = self.sock.recv(4096)
            if a == '':
                raise NetcatError("Connection dropped!")
            self.buf += a

        ret = self.head_buf(self.buf.index(s)+len(s))
        if self.echo and self.echo_recving:
            if self.echo_perline:
                print_lines(ret, '<< ')
            else:
                print '<<', ret
        return ret

    def send(self, s):
        if self.echo and self.echo_headers:
            print '======== Sending ({0}) ========'.format(len(s))

        if self.echo and self.echo_sending:
            if self.echo_perline:
                print_lines(s, '>> ')
            else:
                print '>>', s

        self.sock.send(s)

    read = recv
    read_until = recv_until
    write = send

    def interact(self):
        dropped = False
        if os.fork():
            while not dropped:
                a = self.sock.recv(4096)
                if a == '':
                    dropped = True
                    print '======== Connection dropped! ========'
                else:
                    sys.stdout.write(a)
                    sys.stdout.flush()
            os._exit(0)
        else:
            while not dropped:
                try:
                    b = raw_input()
                except KeyboardInterrupt:
                    dropped = True
                    print '======== Connection interrupted! ========'
                else:
                    self.sock.send(b + '\n')

socket = Netcat

def create_connection(*args):
    nc = Netcat()
    nc.sock = pysocket.create_connection(*args)
    return nc

def print_lines(s, prefix):
    for line in s.split('\n'):
        print prefix + line
