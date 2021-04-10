import hashlib
import sys
import os
your_file = sys.argv[0]
BLOCK_SIZE = 65536 



md5_hash = hashlib.md5()
sha1_hash = hashlib.sha1()
sha256_hash = hashlib.sha256()
sha512_hash = hashlib.sha512()

with open(your_file, 'rb') as f: #read file bytes
    fb = f.read (BLOCK_SIZE) #read file and take in only declared amount
    while len(fb) > 0: #if data is still being read from file
        md5_hash.update(fb)
        fb = f.read(BLOCK_SIZE)#read next block of file

# print different hash formats of the file 
print (md5_hash.hexdigest())

print (sha1_hash.hexdigest())

print (sha256_hash.hexdigest())

print (sha512_hash.hexdigest())


