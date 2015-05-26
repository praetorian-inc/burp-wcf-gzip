# -*- coding: utf-8 -*-
"""
Created on Mon May 17

@author: Anthony Marquez

Burp Plugin to decode WCF binary traffic that is compressed using the 'gzip' algorithm. This is essentially an extension
 of the prior WCF decoding plugin code to include 'gzip' compressed communication. Code is based on plugin seen here:
 https://gist.github.com/sekhmetn/4420532
"""

import base64
import gzip
import subprocess
import sys
from cStringIO import StringIO
from xml.dom import minidom
from subprocess import CalledProcessError

from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from java.io import PrintWriter


class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Gzip Helper")
        callbacks.registerMessageEditorTabFactory(self)
        return

    def createNewInstance(self, controller, editable):
        return GzipHelperTab(self, controller, editable)


class GzipHelperTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self.extender = extender
        self.editable = editable
        self.controller = controller

        self.txtInput = extender.callbacks.createTextEditor()
        self.txtInput.setEditable(editable)

        self.httpHeaders = None
        self.body = None
        self.content = None
        return

    def getTabCaption(self):
        return "Gzip Helper"

    def getUiComponent(self):
        return self.txtInput.getComponent()

    def isModified(self):
        return self.txtInput.isTextModified()

    def getSelectedData(self):
        return self.txtInput.getSelectedText()

    def getHeadersContaining(self, findValue, headers):
        if findValue is not None and headers is not None and len(headers) > 0:
            return [s for s in headers if findValue in s.lower()]
        return None

    def isEnabled(self, content, isRequest):
        #Content-Type: application/x-gzip
        self.content = content
        request_or_response_info = None
        if isRequest:
            request_or_response_info = self.extender.helpers.analyzeRequest(content)
        else:
            request_or_response_info = self.extender.helpers.analyzeResponse(content)
        if request_or_response_info is not None:
            headers = request_or_response_info.getHeaders()
            if headers is not None and len(headers) > 0:
                self.httpHeaders = headers
                self.body = self.extender.helpers.bytesToString(content[request_or_response_info.getBodyOffset():])
                matched_headers = self.getHeadersContaining('content-type', headers)
                if matched_headers is not None:
                    for matched_header in matched_headers:
                        if 'gzip' in matched_header:
                            return True

        return False

    def getPrettyXML(self,xmldata):
        try:
            return minidom.parseString(xmldata).toprettyxml(encoding="utf-8")
        except:
            return xmldata

    def decompress(self, stringContent):
        try:
            buf = StringIO(stringContent)
            s = gzip.GzipFile(mode="r", fileobj=buf)
            content = s.read()
            return content
        except Exception as e:
            self.extender.stdout.println("error({0}): {1}".format(type(e), str(e)))
        return None

    def compress(self, content):
        stringContent = self.extender.helpers.bytesToString(content)
        try:
            buf = StringIO()
            s = gzip.GzipFile(mode="wb", fileobj=buf)
            s.write(stringContent)
            s.close()
            gzipContent = buf.getvalue()
            return gzipContent
        except Exception as e:
            self.extender.stdout.println("error({0}): {1}".format(type(e), str(e)))
        return None

    def decodeWCF(self, binaryString):
        b64_wcfbinary_string = base64.b64encode(binaryString)
        try:
            # NBFS.exe must be in the same directory as Burp
            proc = subprocess.Popen(['NBFS.exe', 'decode', b64_wcfbinary_string], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            b64_out_string = proc.stdout.read()
            self.extender.stdout.println(b64_out_string)
            self.extender.stdout.println(proc.stderr.read())
            output = base64.b64decode(b64_out_string)
            return output

        except CalledProcessError, e:
            self.extender.stdout.println("error({0}): {1}".format(e.errno, e.strerror))
        except:
            self.extender.stdout.println("Unexpected error: %s: %s\n%s" % (sys.exc_info()[0], sys.exc_info()[1], sys.exc_info()[2]))
        return None

    def encodeWCF(self, body):
        xmlStringContent = self.extender.helpers.bytesToString(body)
        base64EncodedXML = base64.b64encode(xmlStringContent.replace("\n", '').replace("\t", ''))
        try:
            # NBFS.exe must be in the same directory as Burp
            proc = subprocess.Popen(['NBFS.exe', 'encode', base64EncodedXML], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = proc.stdout.read()
            self.extender.stdout.println(output)
            self.extender.stdout.println(proc.stderr.read())
            return self.extender.helpers.stringToBytes(base64.b64decode(output))

        except CalledProcessError, e:
            self.extender.stdout.println("error({0}): {1}".format(e.errno, e.strerror))
        except:
            self.extender.stdout.println("Unexpected error: %s: %s\n%s" % (sys.exc_info()[0], sys.exc_info()[1], sys.exc_info()[2]))
        return None

    def setMessage(self, content, isRequest):
        output = self.decodeWCF(self.decompress(self.body))
        self.extender.stdout.println(output)
        self.txtInput.setText(self.getPrettyXML(output))
        return

    def getMessage(self):
        if self.txtInput.isTextModified():
            encoded_txt = self.encodeWCF(self.txtInput.getText())
            return self.extender.helpers.buildHttpMessage(self.httpHeaders, self.compress(encoded_txt))
        else:
            return self.content
