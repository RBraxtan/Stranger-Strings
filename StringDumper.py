import sys,os,math

if len(sys.argv) < 2:
    print("Syntax Error: StringDumper.py <filename>")
else:
    if not os.path.isdir("./outputs"):
        os.makedirs("./outputs")
    os.system("\".\\dependencies\\strings2\" -r " + sys.argv[1] + " > ./outputs/strings.txt")
    os.system("sort ./outputs/strings.txt /O ./outputs/strings.txt")
    os.system("echo \"\" > ./outputs/entropy.txt")

    strings = open("./outputs/strings.txt", "r")
    entropyfile = open("./outputs/entropy.txt", "w")
    IOCBlacklist = open("./dependencies/IOCBlacklist.txt", "r")
    Flagged_Strings = open("./outputs/Flagged Strings.txt", "w")

    flagged = {}

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

        for line in IOCBlacklist:
            if line.strip("\n") in string:
                Flagged_Strings.write(line.strip("\n") + ":" + string)
        IOCBlacklist.seek(0)

    if string_count != 0:
        print("Average Entropy: " + str(round(entropytotal,2)) + "/" + str(string_count) + " (" + str(round(entropytotal/string_count, 2)) + ")")
        
    entropyfile.close()
    os.system("sort /r ./outputs/entropy.txt /O ./outputs/entropy.txt")
    strings.close()
