#!/usr/bin/env python3
#
# Recover the small plaintext via modulus factorization.

# Extended GCD algorithm.
def egcd(b, a):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while a != 0:
        q, b, a = b // a, a, b % a
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return b, x0, y0

# Computes the inverse of a modulo m.
def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

# public key
n = 0x00c2cbb24fdbf923b61268e3f11a3896de4574b3ba58730cbd652938864e2223eeeb704a17cfd08d16b46891a61474759939c6e49aafe7f2595548c74c1d7fb8d24cd15cb23b4cd0a3
e = 65537
# secret message
msg = 0xb32769e676109cc9adf5ea5e1363ddf2d714dbfc7b3ee1edfed9c76f8a69fa58bc295edf0e475d710736ffdb5f1e56414101e612dce15ed77cfe7aa496cab425579adccff49eede0

# factors of n, recovered via http://factordb.com
p = 398075086424064937397125500550386491199064362342526708406385189575946388957261768583317
q = 472772146107435302536223071973048224632914695302097116459852171130520711256363590397527
# compute the private exponent from Euler's totient
phi = (p-1) * (q-1)
d = modinv(e, phi)
# decrypt the message
plaintext = pow(msg, d, n)
# transform the plaintext into a string
print(int.to_bytes(int(plaintext), 100, 'big').decode().lstrip('\x00'))
