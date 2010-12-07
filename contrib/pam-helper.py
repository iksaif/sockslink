#!/usr/bin/env python

import sys
import PAM
import urllib

current_passwd = None

def pam_conv(auth, query_list):
    global current_passwd
    resp = []

    for i in range(len(query_list)):
        query, type = query_list[i]
        if type in [PAM.PAM_PROMPT_ECHO_ON, PAM.PAM_PROMPT_ECHO_OFF]:
            resp.append((current_passwd, 0))
        elif type == PAM.PAM_PROMPT_ERROR_MSG or type == PAM.PAM_PROMPT_TEXT_INFO:
            print "ERR ", query.strip('\n')
            resp.append(('', 0));
        else:
            return None

    return resp


def main():
    global current_passwd

    auth = PAM.pam()
    auth.start('passwd')
    auth.set_item(PAM.PAM_CONV, pam_conv)

    while 1:
         line = sys.stdin.readline()
         if not line:
             break
         line = line[:-1]
         args = line.split(' ')

         try:
             current_passwd = args[3]
             auth.set_item(PAM.PAM_USER, args[2])
             auth.authenticate()
         except PAM.error, (resp, code):
             print 'ERR %s' % resp
         except:
             print 'ERR Internal error'
         else:
             print 'OK ! none'

         sys.stdout.flush()

if __name__ == '__main__':
    main()
