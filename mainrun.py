import sys, os
#your file on the command line
yourfile = sys.argv[1]

os.system("python ./StringDumper.py "  + sys.argv[1])
os.system("python ./Hashing.py " + sys.argv[1])
os.system("python ./ScannerAPI.py " + sys.argv[1])



