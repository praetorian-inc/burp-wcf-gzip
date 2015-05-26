# burp-wcf-gzip


A couple of burp extensions that I created during a couple of security assessments, and I figure I would share them with others to save some pain.

## Instructions

1. Clone repo
2. Copy the NBFS.exe to the same directory as your Burp JAR executable
3. Download Jython standalone JAR if you do not already have it (created using Jython 2.7) - http://www.jython.org/
4. Open Burp and click the Extensions tab.
5. Give Burp the location of your Jython standalone JAR
5. Add extension to Burp - http://portswigger.net/burp/help/extender.html


## Details

Within this repo are 3 files (not including this README):

***

#### WcfGzipBurpPlugin.py
This plugin is used to decompress and decode WCF traffic if it is binary encoded and compressed using 'gzip'.  Burp's builtin 'gzip' decompressing functionality was not correctly identifying the compressed traffic sent by the application I was testing. Each request in any of the Burp tools will have an additional tab that decodes the request and will re-encode on edit.

***

#### GzipBurpPlugin.py
This plugin just the 'gzip' functionality removed from the other plugin. I figure it will likely catch more situations where data is being compressed.

***

#### NBFS.exe
Here is the windows executable used by the plugin to decode and encode WCF binary format. I owe credit for the creation of this file to Brian Holyfield's Burp plugin located here: https://github.com/GDSSecurity/WCF-Binary-SOAP-Plug-In

As stated above, this must be in the same directory as the Burp JAR executable.
