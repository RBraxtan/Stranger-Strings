# FSA-Project-Static-Analysis


Read First before
*Warning!!  When working with potential malware it is important to use a VM or sandbox that is not connected to any network. 
*Warning!! We are not responsible for any improper use or spread of any malware.  
*We are not responsible for the users final conclusion of analysis.


The purpose of this project is to allow an analyst to statically analyze potentional malware sample files.  With the information generated from the report the analyst can determine possible determent stategies.

Instructions:

Step1:  Download Repository
Step2:  Unizip Files and make sure they're all in the same directory/folder
Step3:  Create a free account on VirusTotal to obtain a personal API key.  
Step4:  Important!! Open config file and enter your VirusTotal-API-Key and save.
Step5:  Open command prompt in Windows 10 and go to the directory where files are located.
Step6:  On the command line run the python script "mainrun.py "youfile.exe"  
Step7:  Open outputs to analyze reports, hashes, strings, entropy, and  VirusTotal report to determine if your file sample is malicious. 

What's in the scripts?
Shannon Entropy Values:
IOC blacklist:  A list of strings that are common with malware which can "POSSIBLY" indicate the file is malicious. 
Hashes:  MD5, SHA1,SHA256,SHA512  hash values can be used to compare if your file is a know malware file.
VirusTotal: Generates a report allowing the user to determine if your file sample is a known malware.


