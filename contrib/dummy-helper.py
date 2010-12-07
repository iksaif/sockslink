#!/usr/bin/env python

import sys

def main():
     while 1:
         line = sys.stdin.readline()
         if not line:
             break
         line = line[:-1]
         print 'OK 127.0.0.1 socks username test test123'
         sys.stdout.flush()

if __name__ == '__main__':
    main()
