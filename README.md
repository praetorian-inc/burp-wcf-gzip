burp-wcf-gzip
=====================

A couple of burp extensions that I created during a couple of security assessments, and I figure I would share them with others to save some pain.

Within this repo are 3 files (not including this README):

***

### WcfGzipBurpPlugin.py
This plugin is used to decompress and decode WCF traffic if it is binary encoded and compressed using 'gzip'.  Burp's builtin 'gzip' decompressing functionality was not correctly identifying the compressed traffic sent by the application I was testing.

***

### GzipBurpPlugin.py
This plugin just the 'gzip' functionality removed from the other plugin. I figure it will likely catch more situations where data is being compressed.

***

### NBFS.exe
Here is the windows executable used by the plugin to decode and encode WCF binary format. I owe credit for the creation of this file to Brian Holyfield's Burp plugin located here: https://github.com/GDSSecurity/WCF-Binary-SOAP-Plug-In

***
