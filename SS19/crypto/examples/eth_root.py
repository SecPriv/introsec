#!/usr/bin/env python3
#
# Recover a small plaintext via bruteforce (using e-th integer root).

import gmpy2

# public key
n = 0xdb030db2516421d01b48a005e6191118b5cbcd66634670fc21c067b7bbf3c257ae5695966a1627ab1055f1ce6dbdfe4fa654e1bf81f797fbf69aabeb710227298233dd72d51d429f32759ec44902c2ab39daf6ab75a5a28ac34d87921d54e96adc31a3689479446fc1a171ba4dfa7df1683c79481e5d471738d655c04259c2fb
e = 3
# encrypted message
msg = 0x9e0f7674ee16e763736ce310dce5fcfb6b41a7e666e08fba73a64c19e930f1aff09f9f0eb63acf24ef5735b053a86e10891d09649d4923aa18a3accad9baf6a440f34058dba7681b5d0fd959cf694c21cd045efe1080562fed288f61b3693e4fd8aa769916292160153cf26785b67d1021e0a295f71c6481148823bc15f24a93

while True:
    # compute the e-th root
    r, b = gmpy2.iroot(msg, e)
    # if b is True, r is the exact integer root of msg
    if b:
        # convert int to bytestring, the second parameter is the length of the string
        # I just used 100 for laziness, if the number is smaller some null bytes are prepended
        plain = int.to_bytes(int(r), 100, 'big')
        # convert to utf-8 string and strip null bytes
        print(plain.decode().lstrip('\x00'))
        break
    # add the modulus and try again
    msg += n 
