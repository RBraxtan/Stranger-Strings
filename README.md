# Stranger Strings
<br />
<br />
<br />
*Warning!! When working with potential malware it is important to use a VM or sandbox that is not connected to any network.<br /> 
*Warning!! We are not responsible for any improper use or spread of any malware.<br /><br />
*In addition, we are not responsible for the conclusions formed by analysts who employ our tool.<br />
<br />
<br />
The purpose of this project is to allow an analyst to statically analyze potential malware samples. With the information generated from the report the analyst can gain greater insight to the file in question, but whether the file is actually malicious or not is left to be determined by the professional. This tool is intended for use on Windows 10 and is not tested in other environments.<br />
<br />
Instructions:<br />
<br />
Step 0: Make sure you have python 3+ installed, as well as the virustotal python api (vt-py) which can be installed with "pip install vt-py" from command prompt.<br />
Step 1: Download Repository.<br />
Step 2: Unizip Files and make sure they're all in the same directory/folder.<br />
Step 3: Create a free account on VirusTotal to obtain a personal API key. *optional*<br /><br />
Step 4: Open config file and enter your VirusTotal-API-Key and save.<br />
Step 5: Open command prompt in Windows and go to the directory where files are located.<br />
Step 6: On the command line run the python script "mainrun.py <sample.ext>"<br />
Step 7: Open outputs to analyze reports, hashes, strings, entropy, and VirusTotal report to determine if your file sample is malicious.<br /> 
<br />
What's in the output directory?<br />
entropy.txt: A text document containing the strings from the submitted malware with their relevant shannon entropy value listed before each string. Strings more likely to be human-readable are usually found towards the top.<br />
strings.txt: Raw unfiltered strings dumped by strings2.<br />
Flagged_Strings.txt: Strings matched to those found in the IOCBlacklist<br />
VirusTotal_File_Report: A text document containing basic file information as well as more in-depth results for known malware samples such as crowdsourced IDS and YARA rules.<br />
VirusTotal_Analysis_Report: A text document containing the results of scanning by VirusTotal partnered antivirus engines.<br />
<br />
<br />
Dependencies: This folder contains all the dependencies for the program to run (aside from python and vt-py which must be installed separately).<br />
IOC Blacklist (strict): A list of strings that are common with malware which can POSSIBLY indicate whether the file is malicious or otherwise help inform the analyst of the nature of the file.<br />
IOC Blacklist: A less sensitive blacklist that has fewer strings that are more likely to be associated with malware.<br />
sigcheck.exe: A sysinternals utility used for checking digital signatures. You can find it here https://docs.microsoft.com/en-us/sysinternals/downloads/sigcheck . Please support the appropriate author of this software.<br />
strings2.exe: An improved string extraction tool that can be found here: https://github.com/glmcdona/strings2 <br />

