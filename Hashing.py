import hashlib
import sys
import os
your_file = sys.argv[1]



md5_hash = hashlib.md5()
sha1_hash = hashlib.sha1()
sha256_hash = hashlib.sha256()
sha512_hash = hashlib.sha512()

with open(your_file, 'rb') as f: #read file bytes
    chunk = 0 #read file and take in only declared amount
    while chunk != b'': #if data is still being read from file
        chunk = f.read(1024)
        md5_hash.update(chunk)
        sha1_hash.update(chunk)
        sha256_hash.update(chunk)
        sha512_hash.update(chunk)

# print different hash formats of the file 

print ("MD5 of Your File:")
print (md5_hash.hexdigest())

print ("SHA1 of Your File:")
print (sha1_hash.hexdigest())

print ("SHA256 of Your File:")
print (sha256_hash.hexdigest())

print ("SHA512 of Your File:")
print (sha512_hash.hexdigest())

