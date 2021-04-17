import sys,os,math,hashlib
import re

if len(sys.argv) < 2:
    print("Syntax Error: StringDumper.py <file_name>")
else:
    sha256_hash = hashlib.sha256()

    with open("./samples/" + sys.argv[1], 'rb') as f: #read file bytes
        chunk = 0 #read file and take in only declared amount
        while chunk != b'': #if data is still being read from file
            chunk = f.read(1024)
            sha256_hash.update(chunk)
    print("\nSHA256 Hash: " + sha256_hash.hexdigest() + "\n")

    if not os.path.isdir("./outputs/" + sha256_hash.hexdigest()):
        os.makedirs("./outputs/" + sha256_hash.hexdigest())
    os.system("\".\\dependencies\\strings2\" -r " + sys.argv[1] + " > " + "./outputs/" + sha256_hash.hexdigest() + "/strings.txt")
    os.system("sort ./outputs/" + sha256_hash.hexdigest() + "/strings.txt /O ./outputs/" + sha256_hash.hexdigest() + "/strings.txt")
    os.system("echo \"\" > ./outputs/" + sha256_hash.hexdigest() + "/entropy.txt")

    strings = open("./outputs/" + sha256_hash.hexdigest() + "/strings.txt", "r")
    entropyfile = open("./outputs/" + sha256_hash.hexdigest() + "/entropy.txt", "w")
    IOCBlacklist = open("./dependencies/IOCBlacklist.txt", "r")
    Flagged_Strings = open("./outputs/" + sha256_hash.hexdigest() + "/Flagged Strings.txt", "w")

    string_count = 0
    entropytotal = 0
    for string in strings:
        prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]

        entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
        if(string == "\n"):
            continue
        entropyfile.write(str(entropy) + ":" + string)
        
        entropytotal += entropy
        string_count += 1

        if re.search("^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$", string):
            Flagged_Strings.write("Possible Bitcoin address: " + string)

        if re.search("(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}", string):
            Flagged_Strings.write("Possible IPv4 address: " + string)

        #if re.search("(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))", string):
        #    Flagged_Strings.write("Possible IPv6 address: " + string)

        for line in IOCBlacklist:
            if line.strip("\n").lower() in string.lower():
                Flagged_Strings.write(line.strip("\n") + ":" + string)
        IOCBlacklist.seek(0)

    if string_count != 0:
        print("Average Entropy: " + str(round(entropytotal,2)) + "/" + str(string_count) + " (" + str(round(entropytotal/string_count, 2)) + ")\n")
        
    entropyfile.close()
    os.system("sort /r ./outputs/" + sha256_hash.hexdigest() + "/entropy.txt /O ./outputs/" + sha256_hash.hexdigest() + "/entropy.txt")
    strings.close()
