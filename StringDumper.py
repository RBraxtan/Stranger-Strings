import sys,os,math,hashlib
import re

#Check to make sure a file was properly provided
if len(sys.argv) < 2:
    print("Syntax Error: StringDumper.py <file_name>")
#Begin string dump process
else:
    #Our sha256 hash for output reasons
    sha256_hash = hashlib.sha256()

    with open("./samples/" + sys.argv[1], 'rb') as f: #read file bytes
        chunk = 0 #read file and take in only declared amount
        while chunk != b'': #if data is still being read from file
            chunk = f.read(1024)
            sha256_hash.update(chunk)

    #Check whether this file has been scanned before (whether an output for it already exists) and create an output directory if not
    if not os.path.isdir("./outputs/" + sha256_hash.hexdigest()):
        os.makedirs("./outputs/" + sha256_hash.hexdigest())
    #Run strings2 (dependency) to dump strings and then sort the output using the default method
    os.system("\".\\dependencies\\strings2\" -r " + sys.argv[1] + " > " + "./outputs/" + sha256_hash.hexdigest() + "/strings.txt")
    os.system("sort ./outputs/" + sha256_hash.hexdigest() + "/strings.txt /O ./outputs/" + sha256_hash.hexdigest() + "/strings.txt")
    #Create an empty file for our entropy calculations
    os.system("echo \"\" > ./outputs/" + sha256_hash.hexdigest() + "/entropy.txt")

    #Prepare our strings and empty entropy files for use in the calculation and storage of entropy calculations (respectively)
    strings = open("./outputs/" + sha256_hash.hexdigest() + "/strings.txt", "r")
    entropyfile = open("./outputs/" + sha256_hash.hexdigest() + "/entropy.txt", "w")

    #Check if user specified strict mode or not to determine which IOCBlacklist file to check strings against
    if "True" in sys.argv:
        IOCBlacklist = open("./dependencies/IOCBlacklist_Strict.txt", "r")
    else:
        IOCBlacklist = open("./dependencies/IOCBlacklist.txt", "r")
    Flagged_Strings = open("./outputs/" + sha256_hash.hexdigest() + "/Flagged Strings.txt", "w")

    #Iterate through all strings
    string_count = 0
    entropytotal = 0
    for string in strings:
        #Calculate probability for use in entropy calculation
        prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]

        #Calculate entropy
        entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
        #Skip empty strings
        if(string == "\n"):
            continue
        #Write entropy calculations to the entropy file
        entropyfile.write(str(entropy) + ":" + string)
        
        #Add all the entropy values together for later calculation of an average
        entropytotal += entropy
        string_count += 1

        #Regex search for bitcoin addresses (useful for ransomware)
        if re.search("^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$", string):
            Flagged_Strings.write("Possible Bitcoin address: " + string)

        #Regex search for potential IPv4 addresses
        if re.search("(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}", string):
            Flagged_Strings.write("Possible IPv4 address: " + string)

        #Checking the string for a match in our IOCBlacklist
        for line in IOCBlacklist:
            if line.strip("\n").lower() in string.lower():
                Flagged_Strings.write(line.strip("\n") + ":" + string)
        IOCBlacklist.seek(0)
    Flagged_Strings.close()
    os.system("sort \"./outputs/" + sha256_hash.hexdigest() + "/Flagged Strings.txt\" /O \"./outputs/" + sha256_hash.hexdigest() + "/Flagged Strings.txt\"")

    #Print average entropy assuming that there should be at least one string
    if string_count != 0:
        print("Average Entropy: " + str(round(entropytotal,2)) + "/" + str(string_count) + " (" + str(round(entropytotal/string_count, 2)) + ")\n")
        
    entropyfile.close()
    #Sorting our entropy file from highest entropy to lowest
    os.system("sort /r ./outputs/" + sha256_hash.hexdigest() + "/entropy.txt /O ./outputs/" + sha256_hash.hexdigest() + "/entropy.txt")
    strings.close()
