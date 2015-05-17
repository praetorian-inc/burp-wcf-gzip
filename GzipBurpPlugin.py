# -*- coding: utf-8 -*-
"""
Created on Mon May 17

@author: Anthony Marquez
Majority of this code is modeled from https://gist.github.com/sekhmetn/4420532
"""

import sys
import gzip
from cStringIO import StringIO

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

    def setMessage(self, content, isRequest):
        output = self.decompress(self.body)
        self.extender.stdout.println(output)
        self.txtInput.setText(output)
        return

    def getMessage(self):
        if self.txtInput.isTextModified():
            return self.extender.helpers.buildHttpMessage(self.httpHeaders, self.compress(self.txtInput.getText()))
        else:
            return self.content
