import json

from java.io import PrintWriter
from java.net import URL





from burp import IBurpExtender, IScannerCheck, IScanIssue, IExtensionStateListener,IHttpRequestResponse

from  path  import processPath
from  content  import processContent
from utils import  findAllCharIndexesInString,array2Str
import random



class BurpExtender(IBurpExtender,IScannerCheck,IExtensionStateListener):



    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("403fuzzer")

        self._positve_urls = set()
        self._observed_urls = set()   
        self._observed_hosts  = set()

        self._ok_paths = set()    #200 or 201 path prefix  /a /a/b
        self._ok_path_maxcount = 3

        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        import sys
        sys.stdout = callbacks.getStdout()
        sys.stderr = callbacks.getStderr()
        self._callbacks.registerScannerCheck(self)
        self._callbacks.registerExtensionStateListener(self)

        self.loadFromSitemap()

        self._stdout.println("403fuzzer Extension loaded")

        return


    def serializeData(self):
        data = {}
        data["_ok_paths"]=list(self._ok_paths)
        data["_observed_hosts"]=list(self._observed_hosts)
        data["_positve_urls"]=list(self._positve_urls)
        data["_observed_urls"]=list(self._observed_urls)
        data = json.dumps(data)

        return data


    def deserializeData(self,data):
        data = array2Str(data)
        self._stdout.println(data)
        data = json.loads(data)
        self._ok_paths.update(data["_ok_paths"])
        self._observed_hosts.update(data["_observed_hosts"])
        self._positve_urls.update(data["_positve_urls"])
        self._observed_urls.update(data["_observed_urls"])

    def saveToSitemap(self):

        request_response = self._callbacks.getSiteMap("https://com.coreyd97")[0]
        httpService = request_response.getHttpService()
        request = self._helpers.bytesToString(request_response.getRequest())
        lines = request.split('\n')
        lines[0] = 'GET /403fuzzer HTTP/1.1'
        request = '\n'.join(lines)
        request = self._helpers.stringToBytes(request)

        data = self.serializeData()
        setting = ExtensionSetting(httpService,request,data)

        self._callbacks.addToSiteMap(setting)

    def loadFromSitemap(self):
        items = self._callbacks.getSiteMap("https://com.coreyd97.burpextenderutilities:65535/403fuzzer")
        if items:
            self._stdout.println("debug: trying to load data from site map   https://com.coreyd97.burpextenderutilities:65535/403fuzzer ")
            item = items[0]
            data = item.getResponse()
            if data:
                self.deserializeData(data)

    def extensionUnloaded(self):
        self._stdout.println("403fuzzer extension was unloaded")
        self.saveToSitemap()

    def isPositive(self, status_code):
        if status_code not in [400,401,402,403,404,405,406,500,501,503]:
            return True
        return  False

    def isInteresting(self, status_code,old_url):
        #response = self._helpers.bytesToString(response)
        if old_url in self._positve_urls :
            return False
        return status_code == 403 or status_code == 401

    def hasPath(self,path):
        if path != '/' and path:
            return True
        return False



    def observeOkPath(self,path):
    # returns /a  /a/b  /a/b/c
        if path in self._ok_paths :
            return
        slash_indexs =  findAllCharIndexesInString(path,'/')
        if path.endswith("/"):
            for i in range(1,len(slash_indexs)):
                if i  <= self._ok_path_maxcount:   #limit the string count in /aaa/bbb/ccc
                    cur_path = path[:slash_indexs[i]]
                    if '.' not in cur_path:
                        self._ok_paths.add(cur_path)
        else:
            if len(slash_indexs) == self._ok_path_maxcount:
                if '.' not in path:
                    self._ok_paths.add(path)
            for i in range(1,len(slash_indexs)):
                if i  <= self._ok_path_maxcount:   #limit the string count in /aaa/bbb/ccc
                    cur_path = path[:slash_indexs[i]]
                    if '.' not in cur_path:
                        self._ok_paths.add(cur_path)
                    continue



    def observeHost(self,host):
        self._observed_hosts.add(host)

    def fuzzPath(self,baseRequestResponse):
        base_path = self._helpers.analyzeRequest(baseRequestResponse).getUrl().getPath()
        base_req =  self._helpers.bytesToString(baseRequestResponse.getRequest())
        base_url = self._helpers.analyzeRequest(baseRequestResponse).getUrl().toString()
        http_service = baseRequestResponse.getHttpService()
        
        
        issues = []
        # self._debug(base_path)

        payload_paths = processPath(base_path,self._ok_paths)

        for payload_path in payload_paths:
            self._debug(payload_path)
            payload_req =  base_req.replace(base_path,payload_path)
            payload_req_byte =  self._helpers.stringToBytes(payload_req)
            verifyingRequestResponse =  self._callbacks.makeHttpRequest(http_service, payload_req_byte)
            stt_code = self._helpers.analyzeResponse(verifyingRequestResponse.getResponse()).getStatusCode()
            if self.isPositive(stt_code):
                self._positve_urls.add(base_url)
                issues.append(self.generateIssue(baseRequestResponse,verifyingRequestResponse))

        return issues

    def fuzzContent(self,baseRequestResponse):
        http_service = baseRequestResponse.getHttpService()
        base_url = self._helpers.analyzeRequest(baseRequestResponse).getUrl().toString()
        base_req =  self._helpers.bytesToString(baseRequestResponse.getRequest())
        base_path = self._helpers.analyzeRequest(baseRequestResponse).getUrl().getPath()
        ip = http_service.getHost()
        base_port = str(http_service.getPort())
        domain = self._helpers.analyzeRequest(baseRequestResponse).getUrl().getHost()

        issues = []

        payload_reqs = processContent(reqcontent=base_req, url=base_url,path=base_path,domain=domain, ip=ip,okpaths=self._ok_paths,observed_hosts=self._observed_hosts,basePort=base_port)



        for payload_req in  payload_reqs:
            # self._debug(payload_req)
            payload_req_byte =  self._helpers.stringToBytes(payload_req)

            verifyingRequestResponse =  self._callbacks.makeHttpRequest(http_service, payload_req_byte)
            stt_code = self._helpers.analyzeResponse(verifyingRequestResponse.getResponse()).getStatusCode()
            if self.isPositive(stt_code):
                self._positve_urls.add(base_url)
                # results.add( str(stt_code)+ "Url content payload: "+self._helpers.bytesToString(payload_req_result).getRequest())
                issues.append(self.generateIssue(baseRequestResponse,verifyingRequestResponse))

        return issues


    def doPassiveScan(self, baseRequestResponse):
        return []

    def _debug(self,a):
        self._stdout.println(a)



    def doActiveScan(self, baseRequestResponse,insertionPoint):
        self._stdout.println("Active scanning started")
        status_code = self._helpers.analyzeResponse(baseRequestResponse.getResponse()).getStatusCode()
        old_path = self._helpers.analyzeRequest(baseRequestResponse).getUrl().getPath()
        old_host = self._helpers.analyzeRequest(baseRequestResponse).getUrl().getHost()
        old_url = self._helpers.analyzeRequest(baseRequestResponse).getUrl().toString()


        if not self._callbacks.isInScope(self._helpers.analyzeRequest(baseRequestResponse).getUrl()):
            return None
        if old_url in self._observed_urls:
            return None

        self._observed_urls.add(old_url)


        if not self.hasPath(old_path):
            return None


        if not self.isInteresting(status_code, old_url):
            if status_code in [200,201,203,204,301,302,303,304,305,306]:
                self.observeOkPath(old_path)
                self.observeHost(old_host)
                self._debug("not Interesting")
            return None


        # issues = []

        issues = self.fuzzPath(baseRequestResponse) + self.fuzzContent(baseRequestResponse)
        if len(issues) > 0:
            return issues
        else:
            return None

    def generateIssue(self,baseRequestResponse,verifyingRequestResponse):
        name = "403 bypass "
        severity = "High"
        confidence = "Firm"
        detail = """
found potential 403 bypass 
<ul>
<li>Original url: %s</li>
<li>Verification url: %s</li>
</ul>        
""" % (
            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
            self._helpers.analyzeRequest(verifyingRequestResponse).getUrl(),
        )
        return CustomScanIssue(
            baseRequestResponse.getHttpService(),
            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
            [baseRequestResponse, verifyingRequestResponse],
            name,
            detail,
            severity,
        )


    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        # This method is called when multiple issues are reported for the same URL
        # path by the same extension-provided check. The value we return from this
        # method determines how/whether Burp consolidates the multiple issues
        # to prevent duplication
        #
        # Since the issue name is sufficient to identify our issues as different,
        # if both issues have the same name, only report the existing issue
        # otherwise report both issues
        # if existingIssue.getUrl() == newIssue.getUrl():
        #     return -1
        byte_existing = existingIssue.getHttpMessages()[1].getRequest()
        byte_new = newIssue.getHttpMessages()[1].getRequest()
        if byte_existing == byte_new:
            return -1
        return 0

class CustomScanIssue (IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Firm"

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService


class ExtensionSetting(IHttpRequestResponse):
    # def __init__(self, httpService, url, httpMessages, name, detail, severity):
    #     self._httpService = httpService
    #     self._url = url
    #     self._httpMessages = httpMessages
    #     self._name = name
    #     self._detail = detail
    #     self._severity = severity

    def __init__(self,httpService,requestBytes,data):
        self._httpService = httpService
        self._requestBytes = requestBytes
        self._data = data

    def getComment(self):
        return None

    def getHighlight(self):
        return None

    def getRequest(self):
        return self._requestBytes

    def getResponse(self):
        return self._data

    def getHttpService(self):
        return self._httpService

    def setRequest(self, requestBytes):
        self._requestBytes = requestBytes

    def setHttpService(self, httpService):
        self._httpService = httpService

    def setHighlight(self, color):
        pass

    def setResponse(self, data):
        self._data = data

    def setComment(self, comment):
        pass
