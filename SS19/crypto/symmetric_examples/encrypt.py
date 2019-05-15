#!/usr/bin/env python3

import os
import sys
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def die(msg):
    sys.stderr.write('[!] {}\n'.format(msg))
    sys.exit(1)


def file_parse(data, ftype='bmp'):
    if ftype == 'bmp':
        header, content = data[:138], data[138:]
    else:
        die('File type {} is not supported'.format(ftype))

    return header, content


def encrypt(data, key=os.urandom(16), mode='ecb'):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data)
    padded_data += padder.finalize()

    if mode == 'ecb':
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    elif mode == 'cbc':
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = iv + encryptor.update(padded_data) + encryptor.finalize()
    else:
        die('Unsupported cipher block mode')

    return ciphertext


def main():
    if len(sys.argv) != 4:
        die('Usage: {} <mode> <infile> <outfile>'.format(sys.argv[0]))

    with open(sys.argv[2], 'rb') as f:
        data = f.read()
    
    header, plain = file_parse(data, ftype=sys.argv[2].split('.')[-1].lower())
    
    with open(sys.argv[3], 'wb') as f:
        f.write(header + encrypt(plain, mode=sys.argv[1]))


if __name__ == '__main__':
    main()