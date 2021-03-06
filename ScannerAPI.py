
try: # attempt to import vt, will fail if the user has not installed vt-py and close the program
    import vt
except:
    print("\nvt-py not installed, install using \"pip install vt-py\". Skipping virustotal scan...\n")
    exit()
import json,sys,os
import hashlib

#Making sure there is a file specified
if len(sys.argv) < 2:
    print("No file specified.")
    exit()

#Making sure the sample file provided exists
if(not os.path.exists("./samples/" + sys.argv[1])):
    print("Specified file not found. Make sure it is in the samples directory.")
    exit()

#Creating a config dictionary to store Virustotal API key for the user
config = {}

with open("config.txt", "r") as f:
    config = json.load(f)

#Sha256 hash
sha256_hash = hashlib.sha256()

with open("./samples/" + sys.argv[1], 'rb') as f: #read file bytes
    chunk = 0 #read file and take in only declared amount
    while chunk != b'': #if data is still being read from file
        chunk = f.read(1024)
        sha256_hash.update(chunk)

#Checking that a VirusTotal API Key was provided in the config file
if config["VirusTotal-API-Key"] == "":
    print("No VirusTotal API key specified, skipping...")
else:
    #Checking whether there is already an output directory, creating one if not
    if not os.path.isdir("./outputs/" + sha256_hash.hexdigest()):
        os.makedirs("./outputs/" + sha256_hash.hexdigest())
    client = vt.Client(config["VirusTotal-API-Key"])
    
    #Check whether the sample has been provided to VirusTotal before, if not it will be automatically submitted
    try:
        sample = client.get_object("/files/" + sha256_hash.hexdigest())
    except:
        print("\n\nFile not found in VirusTotal database, running an analysis now (this may take a while)...")

        #Submitting the file to VirusTotal and generating the first report
        with open("./samples/" + sys.argv[1], "rb") as f:
            print()
            analysis = client.scan_file(f, wait_for_completion=True)
            sample = client.get_object("/files/" + sha256_hash.hexdigest())
            #Analyses from https://developers.virustotal.com/v3.0/reference#analyses-object
            report = open("./outputs/" + sha256_hash.hexdigest() + "/VirusTotal_Analysis_Report.txt", "w")
            report.write("########################################\nStats\n########################################\n")
            report.write(json.dumps(analysis.stats, indent=4, sort_keys=True, default=str) + "\n")
            report.write("########################################\nEngine Results\n########################################\n")
            report.write(json.dumps(analysis.results, indent=4, sort_keys=True, default=str) + "\n")
            report.close()

        #Generating the second report
        file_report = open("./outputs/" + sha256_hash.hexdigest() + "/VirusTotal_File_Report.txt", "w")
        file_report.write("########################################\nFile Info\n########################################\n")
        try:
            file_report.write("File Creation Date: " + str(sample.creation_date) + "\n")
        except:
            file_report.write("No Creation Date found.\n")
        try:
            file_report.write("File Last Modified Date: " + str(sample.last_modification_date) + "\n")
        except:
            file_report.write("No Last Modified Date found.\n")
        try:
            file_report.write("First Submission Date: " + str(sample.first_submission_date) + "\n")
        except:
            file_report.write("No First Submission Date found.\n")
        try:
            file_report.write("Last Analysis Date: " + str(sample.last_analysis_date) + "\n")
        except:
            file_report.write("No Last Analysis Date found.\n")
        try:
            file_report.write("File Reputation: " + str(sample.reputation) + "\n")
        except:
            file_report.write("No Reputation found.\n")
        try:
            file_report.write("File Type: " + sample.type_tag + "\n")
        except:
            file_report.write("File Type Unknown.\n")

        file_report.write("########################################\nCrowdsourced IDS Results\n########################################\n")
        try:
            file_report.write(json.dumps(sample.crowdsourced_ids_stats, indent=4, sort_keys=True, default=str) + "\n\n")
            file_report.write(json.dumps(sample.crowdsourced_ids_results, indent=4, sort_keys=True, default=str) + "\n")
        except:
            file_report.write("No crowdsourced IDS Results found.\n")

        file_report.write("########################################\nCrowdsourced YARA Results\n########################################\n")
        try:
            file_report.write(json.dumps(sample.crowdsourced_yara_results, indent=4, sort_keys=True, default=str) + "\n")
        except:
            file_report.write("No crowdsourced YARA Results found.\n")

        file_report.write("########################################\nSandbox Verdicts\n########################################\n")
        try:
            file_report.write(json.dumps(sample.sandbox_verdicts, indent=4, sort_keys=True, default=str) + "\n")
        except:
            file_report.write("No Sandbox Verdicts found.\n")

        file_report.write("########################################\nSigma Analysis\n########################################\n")
        try:
            file_report.write(json.dumps(sample.sigma_analysis_stats, indent=4, sort_keys=True, default=str) + "\n")
        except:
            file_report.write("No Sigma Analysis found.\n")

        file_report.write("########################################\nFiles Names\n########################################\n")
        try:
            file_report.write("Meaningful Name: " + sample.meaningful_name + "\n")
        except:
            file_report.write("No meaningful names found.\n")
        file_report.write(json.dumps(sample.names, indent=4, sort_keys=True, default=str) + "\n")
        
        file_report.close()
        client.close()
        exit()

    #If the file has previously been submitted, will ask the user whether they want to reanalyze or just display results of previous scan.
    #From there, essentially the same function as above is done.
    userAnswer = input("This sample has been submitted to VirusTotal before, would you like to reanalyze? (y/n):")
    if userAnswer == "y" or userAnswer == "Y":
        with open("./samples/" + sys.argv[1], "rb") as f:
            print()
            analysis = client.scan_file(f, wait_for_completion=True)
            #Analyses from https://developers.virustotal.com/v3.0/reference#analyses-object
            report = open("./outputs/" + sha256_hash.hexdigest() + "/VirusTotal_Analysis_Report.txt", "w")
            report.write("########################################\nStats\n########################################\n")
            report.write(json.dumps(analysis.stats, indent=4, sort_keys=True, default=str) + "\n")
            report.write("########################################\nEngine Results\n########################################\n")
            report.write(json.dumps(analysis.results, indent=4, sort_keys=True, default=str) + "\n")
            report.close()

        file_report = open("./outputs/" + sha256_hash.hexdigest() + "/VirusTotal_File_Report.txt", "w")
        file_report.write("########################################\nFile Info\n########################################\n")
        try:
            file_report.write("File Creation Date: " + str(sample.creation_date) + "\n")
        except:
            file_report.write("No Creation Date found.\n")
        try:
            file_report.write("File Last Modified Date: " + str(sample.last_modification_date) + "\n")
        except:
            file_report.write("No Last Modified Date found.\n")
        try:
            file_report.write("First Submission Date: " + str(sample.first_submission_date) + "\n")
        except:
            file_report.write("No First Submission Date found.\n")
        try:
            file_report.write("Last Analysis Date: " + str(sample.last_analysis_date) + "\n")
        except:
            file_report.write("No Last Analysis Date found.\n")
        try:
            file_report.write("File Reputation: " + str(sample.reputation) + "\n")
        except:
            file_report.write("No Reputation found.\n")
        try:
            file_report.write("File Type: " + sample.type_tag + "\n")
        except:
            file_report.write("File Type Unknown.\n")

        file_report.write("########################################\nCrowdsourced IDS Results\n########################################\n")
        try:
            file_report.write(json.dumps(sample.crowdsourced_ids_stats, indent=4, sort_keys=True, default=str) + "\n\n")
            file_report.write(json.dumps(sample.crowdsourced_ids_results, indent=4, sort_keys=True, default=str) + "\n")
        except:
            file_report.write("No crowdsourced IDS Results found.\n")

        file_report.write("########################################\nCrowdsourced YARA Results\n########################################\n")
        try:
            file_report.write(json.dumps(sample.crowdsourced_yara_results, indent=4, sort_keys=True, default=str) + "\n")
        except:
            file_report.write("No crowdsourced YARA Results found.\n")

        file_report.write("########################################\nSandbox Verdicts\n########################################\n")
        try:
            file_report.write(json.dumps(sample.sandbox_verdicts, indent=4, sort_keys=True, default=str) + "\n")
        except:
            file_report.write("No Sandbox Verdicts found.\n")

        file_report.write("########################################\nSigma Analysis\n########################################\n")
        try:
            file_report.write(json.dumps(sample.sigma_analysis_stats, indent=4, sort_keys=True, default=str) + "\n")
        except:
            file_report.write("No Sigma Analysis found.\n")

        file_report.write("########################################\nFiles Names\n########################################\n")
        try:
            file_report.write("Meaningful Name: " + sample.meaningful_name + "\n")
        except:
            file_report.write("No meaningful names found.\n")
        file_report.write(json.dumps(sample.names, indent=4, sort_keys=True, default=str) + "\n")
        
        file_report.close()
        client.close()
    else:
        print("")
        #Files from https://developers.virustotal.com/v3.0/reference#files
        report = open("./outputs/" + sha256_hash.hexdigest() + "/VirusTotal_Analysis_Report.txt", "w")
        report.write("########################################\nStats\n########################################\n")
        report.write(json.dumps(sample.last_analysis_stats, indent=4, sort_keys=True, default=str) + "\n")

        report.write("########################################\nEngine Results\n########################################\n")
        report.write(json.dumps(sample.last_analysis_results, indent=4, sort_keys=True, default=str) + "\n")
        report.close()


        file_report = open("./outputs/" + sha256_hash.hexdigest() + "/VirusTotal_File_Report.txt", "w")
        file_report.write("########################################\nFile Info\n########################################\n")
        try:
            file_report.write("File Creation Date: " + str(sample.creation_date) + "\n")
        except:
            file_report.write("No Creation Date found.\n")
        try:
            file_report.write("File Last Modified Date: " + str(sample.last_modification_date) + "\n")
        except:
            file_report.write("No Last Modified Date found.\n")
        try:
            file_report.write("First Submission Date: " + str(sample.first_submission_date) + "\n")
        except:
            file_report.write("No First Submission Date found.\n")
        try:
            file_report.write("Last Analysis Date: " + str(sample.last_analysis_date) + "\n")
        except:
            file_report.write("No Last Analysis Date found.\n")
        try:
            file_report.write("File Reputation: " + str(sample.reputation) + "\n")
        except:
            file_report.write("No Reputation found.\n")
        try:
            file_report.write("File Type: " + sample.type_tag + "\n")
        except:
            file_report.write("File Type Unknown.\n")

        file_report.write("########################################\nCrowdsourced IDS Results\n########################################\n")
        try:
            file_report.write(json.dumps(sample.crowdsourced_ids_stats, indent=4, sort_keys=True, default=str) + "\n\n")
            file_report.write(json.dumps(sample.crowdsourced_ids_results, indent=4, sort_keys=True, default=str) + "\n")
        except:
            file_report.write("No crowdsourced IDS Results found.\n")

        file_report.write("########################################\nCrowdsourced YARA Results\n########################################\n")
        try:
            file_report.write(json.dumps(sample.crowdsourced_yara_results, indent=4, sort_keys=True, default=str) + "\n")
        except:
            file_report.write("No crowdsourced YARA Results found.\n")

        file_report.write("########################################\nSandbox Verdicts\n########################################\n")
        try:
            file_report.write(json.dumps(sample.sandbox_verdicts, indent=4, sort_keys=True, default=str) + "\n")
        except:
            file_report.write("No Sandbox Verdicts found.\n")

        file_report.write("########################################\nSigma Analysis\n########################################\n")
        try:
            file_report.write(json.dumps(sample.sigma_analysis_stats, indent=4, sort_keys=True, default=str) + "\n")
        except:
            file_report.write("No Sigma Analysis found.\n")

        file_report.write("########################################\nFiles Names\n########################################\n")
        try:
            file_report.write("Meaningful Name: " + sample.meaningful_name + "\n")
        except:
            file_report.write("No meaningful names found.\n")
        file_report.write(json.dumps(sample.names, indent=4, sort_keys=True, default=str) + "\n")
        
        file_report.close()
        client.close()

client.close()