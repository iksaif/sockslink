#!/usr/bin/env python

import sys
import urllib
import re
proxies = {
    'localhost' : '127.0.0.1:1080',
    'localhostv6' : '[::1]:1080',
}

users = {
    'test' : 'test123',
    'test2' : 'test2',
}


def htc(m):
    return chr(int(m.group(1), 16))

def urldecode(url):
    rex = re.compile('%([0-9a-hA-H][0-9a-hA-H])', re.M)
    return rex.sub(htc,url)

def auth_none(args):
    print 'OK ! none'

def auth_username(args):
    args[2] = urldecode(args[2])

    if '@' in args[2]:
        parts = args[2].split('@')
        uname = '@'.join(parts[:-1])
        server = parts[-1:][0]
        if server in proxies:
            server = proxies[server]
        else:
            server = None
    else:
        uname = args[2]
        server = '!'

    passwd = urldecode(args[3])

    if not server:
        print 'ERR Unknown server'
        return

    for user in users.keys():
        if user == uname:
            if users[user] == passwd:
                print 'OK %s username %s' % (server, uname)
            else:
                print 'ERR Authentication failure (bad password)'
            return
    print 'ERR Authentication failure (no such user)'

def main():
    while 1:
         line = sys.stdin.readline()
         if not line:
             break
         line = line[:-1]
         args = line.split(' ')

         if len(args) == 2 and args[1] == 'none':
             auth_none(args)
         elif len(args) == 4 and args[1] == 'username':
             try:
                 auth_username(args)
             except:
                 print "ERR Fatal error"
         else:
             print 'ERR Invalid number of argument'
         sys.stdout.flush()

if __name__ == '__main__':
    main()
