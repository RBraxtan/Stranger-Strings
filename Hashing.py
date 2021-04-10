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
        sha1_hash.update(fb)
        sha256_hash.update(fb)
        sha512_hash.update(fb)
        fb = f.read(BLOCK_SIZE)#read next block of file

# print different hash formats of the file 

print ("MD5 of Your File:")
print (md5_hash.hexdigest())

print ("SHA1 of Your File:")
print (sha1_hash.hexdigest())

print ("SHA256 of Your File:")
print (sha256_hash.hexdigest())

print ("SHA512 of Your File:")
print (sha512_hash.hexdigest())


