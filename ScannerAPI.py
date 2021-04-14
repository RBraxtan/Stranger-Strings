import vt
import json,sys,os
import hashlib

if len(sys.argv) < 2:
    print("No file specified.")
    exit()

if(not os.path.exists(sys.argv[1])):
    print("Specified file not found.")
    exit()

config = {}

with open("config.txt", "r") as f:
    config = json.load(f)

sha256_hash = hashlib.sha256()

with open(sys.argv[1], 'rb') as f: #read file bytes
    chunk = 0 #read file and take in only declared amount
    while chunk != b'': #if data is still being read from file
        chunk = f.read(1024)
        sha256_hash.update(chunk)

if config["VirusTotal-API-Key"] == "":
    print("No VirusTotal API key specified, skipping...")
else:
    client = vt.Client(config["VirusTotal-API-Key"])
    sample = client.get_object("/files/" + sha256_hash.hexdigest())

    if(sample.times_submitted > 1):
        userAnswer = input("This sample has been submitted to VirusTotal before, would you like to reanalyze? (y/n):")
        if userAnswer == "y" or userAnswer == "Y":
            with open(sys.argv[1], "rb") as f:
                print()
                analysis = client.scan_file(f, wait_for_completion=True)
                #Need to select what to actually display here from https://developers.virustotal.com/v3.0/reference#analyses-object
                print(analysis)
        else:
            print("")
            #Need to select what to display here from https://developers.virustotal.com/v3.0/reference#files
            print(sample.last_analysis_stats)

    else:
        with open(sys.argv[1], "rb") as f:
                print()
                analysis = client.scan_file(f, wait_for_completion=True)
                #Need to actually select what to display here from https://developers.virustotal.com/v3.0/reference#analyses-object
                print(analysis)
    client.close()