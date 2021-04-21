import sys, os, hashlib

if len(sys.argv) < 2:
    print("Correct Syntax: mainrun.py <filename> <arguments>")
    print()
    print("Available arguments:")
    print()
    print("-sv, --skip-virustotal")
    print("     Skips virustotal scan")
    print()
    print("-s, --strict")
    print("     Enables strict mode for string flagging, which increases the sample size of strings. Warning: this will slow down the scan and not every result will be necessarily indicative of malware")
    print()
    print("-o, --open")
    print("     Automatically opens the output folder when the scan finishes")

    exit()

if(not os.path.exists("./samples/" + sys.argv[1])):
    print("Specified file \"" + sys.argv[1] + "\" not found. Make sure it is in the samples directory.")
    exit()

sha256_hash = hashlib.sha256()

with open("./samples/" + sys.argv[1], 'rb') as f: #read file bytes
    chunk = 0 #read file and take in only declared amount
    while chunk != b'': #if data is still being read from file
        chunk = f.read(1024)
        sha256_hash.update(chunk)

os.system("python ./Hashing.py "  + sys.argv[1])

os.system("python ./StringDumper.py " + sys.argv[1] + " " + str("-s" in sys.argv or "--strict" in sys.argv))

if not "-sv" in sys.argv and not "--skip-virustotal" in sys.argv:
    os.system("python ./ScannerAPI.py " + sys.argv[1])

path = "./outputs/" + sha256_hash.hexdigest()
path = os.path.realpath(path)
if "-o" in sys.argv or "--open" in sys.argv:
    os.startfile(path)
else:
    print("Scan complete. Analysis can be found in " + str(path))

