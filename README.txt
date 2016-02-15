				README


burpsift.pl is developed to sift out the Burp log (https://portswigger.net/burp/scanner.html) for the grains of gold (security findings). You can consider it as a passive application vulnerability scanneraddon to Burp. 

Usage:
I would typically turn on the logging mode and let Burp crawl the whole application for me. Once done, I can then lauch this tool to sift through the log contents. 
	
Syntax:
	$ burpsift.pl ?|-h|--help
			-h|?|help		Print help message
			-i|input		Mandatory Burp log file as program input
			-o|output		Optional program output files' prefix
			-l|filter		Optional, URL filter to narrow down the relevant application only.
			-vv|verbose		Program in verbose mode
			-v|version		Program version	

Usage Example:
To sift out the Burp log 'myapp_burp_log' for application 'www.myapp.com', and save outcome to files with prefix 'myapp_output':
          $ ./burpsift.pl -i myapp_burp_log -o myapp_output -l myapp.com
