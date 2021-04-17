import sys, os
#your file on the command line

if len(sys.argv) < 2:
    print("No file specified. Correct Syntax: mainrun.py <filename>")
    exit()

if(not os.path.exists("./samples/" + sys.argv[1])):
    print("Specified file not found. Make sure it is in the samples directory.")
    exit()

os.system("python ./Hashing.py "  + sys.argv[1])
os.system("python ./StringDumper.py " + sys.argv[1])
os.system("python ./ScannerAPI.py " + sys.argv[1])



