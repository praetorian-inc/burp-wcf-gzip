# -*- coding: utf-8 -*-
"""
Created on Mon March 16

@author: Anthony Marquez
Majority of this code is borrowed from https://gist.github.com/sekhmetn/4420532
It is also fully dependent on having NBFS.exe from his plugin in the same directory as Burp.
"""

from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from java.io import PrintWriter
from xml.dom import minidom
import subprocess
import base64
from subprocess import CalledProcessError
import sys
import gzip
from cStringIO import StringIO


class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks=callbacks
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("WCF Gzip Helper")
        callbacks.registerMessageEditorTabFactory(self)
        return

    def createNewInstance(self, controller, editable):
        return WCFGzipHelperTab(self, controller, editable)


class WCFGzipHelperTab(IMessageEditorTab):
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
        return "WCF Gzip Helper"

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
        #Content-Type: application/msbin1
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

    def getPrettyXML(self, xmldata):
        try:
            return minidom.parseString(xmldata).toprettyxml(encoding="utf-8")
        except:
            return xmldata

    def decodeWCF(self, base64EncodedBody):
        try:
            #NBFS.exe must be in the same directory as Burp
            proc = subprocess.Popen(['NBFS.exe', 'decode', base64EncodedBody], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            #proc.wait()
            output = proc.stdout.read()
            self.extender.stdout.println(output)
            self.extender.stdout.println(proc.stderr.read())
            return output

        except CalledProcessError, e:
            self.extender.stdout.println("error({0}): {1}".format(e.errno, e.strerror))
        except:
            self.extender.stdout.println("Unexpected error: %s: %s\n%s" % (sys.exc_info()[0], sys.exc_info()[1], sys.exc_info()[2]))
        #self.extender.stdout.println(output)
        return None

    def encodeWCF(self, xmlContent):
        xmlStringContent = self.extender.helpers.bytesToString(xmlContent)
        base64EncodedXML = base64.b64encode(xmlStringContent.replace("\n", '').replace("\t", ''))
        try:
            #NBFS.exe must be in the same directory as Burp
            proc = subprocess.Popen(['NBFS.exe', 'encode', base64EncodedXML], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            #proc.wait()
            output = proc.stdout.read()
            self.extender.stdout.println(output)
            self.extender.stdout.println(proc.stderr.read())
            return self.extender.helpers.stringToBytes(base64.b64decode(output))

        except CalledProcessError, e:
            self.extender.stdout.println("error({0}): {1}".format(e.errno, e.strerror))
        except:
            self.extender.stdout.println("Unexpected error: %s: %s\n%s" % (sys.exc_info()[0], sys.exc_info()[1], sys.exc_info()[2]))
        #self.extender.stdout.println(output)
        return None

    def decompressWCF(self, stringContent):
        try:
            buf = StringIO(stringContent)
            s = gzip.GzipFile(mode="rb", fileobj=buf)
            content = s.read()
            return content
        except Exception as e:
            self.extender.stdout.println("error({0}): {1}".format(e.errno, e.strerror))
        #self.extender.stdout.println(output)
        return None

    def compressWCF(self, content):
        stringContent = self.extender.helpers.bytesToString(content)
        try:
            buf = StringIO()
            s = gzip.GzipFile(mode="wb", fileobj=buf)
            s.write(stringContent)
            s.close()
            gzipContent = s.read()
            return gzipContent
        except Exception as e:
            self.extender.stdout.println("error({0}): {1}".format(e.errno, e.strerror))
        #self.extender.stdout.println(output)
        return None

    def setMessage(self, content, isRequest):
        output = self.decompressWCF(self.body)
        base64encoded_wcfbinary_data = base64.b64encode(output)
        self.extender.stdout.println(base64encoded_wcfbinary_data)
        output1 = self.decodeWCF(base64encoded_wcfbinary_data)
        output2 = base64.b64decode(output1)
        self.txtInput.setText(self.getPrettyXML(output2))
        return

    def getMessage(self):
        if self.txtInput.isTextModified():
            encodedText = self.encodeWCF(self.txtInput.getText())
            return self.extender.helpers.buildHttpMessage(self.httpHeaders, self.compressWCF(encodedText))
        else:
            return self.content
