import re
import random
from utils import  findAllCharIndexesInString
from utils import  generatedotdotSlash


def lowerCasePost(content,url):
    content = content.replace("POST","PoST",1)
    if ".php" in url:
        content = content.replace(".php","%2ephp",1)
    if ".jsp" in url:
        content = content.replace(".jsp","%2ejsp",1)
    if ".asp" in url:
        content = content.replace(".asp","%2easp",1)
    return content


def absoluteUrl(reqcontent,observed_hosts,url,path,host):
    payload_reqs = set()
    absolute_url = url
    absolute_url_1 = url.replace("http","random")


    for observed_host in observed_hosts:
        # if observed_host == host:
        #     continue
        new_host_str = "Host: " + observed_host
        reqcontent = re.sub("Host: .+", new_host_str, reqcontent, 1)
        reqcontent = reqcontent.replace(path,absolute_url)
        reqcontent_1 = reqcontent.replace(path,absolute_url_1)
        payload_reqs.add(reqcontent)
        payload_reqs.add(reqcontent_1)
    return payload_reqs


def tabHttp1(content,path,okpath):
    a = '/\tHTTP/1.1/'
    b = '..'
    path = path+a
    slash_count = len(findAllCharIndexesInString(path, '/'))
    newpath = path + generatedotdotSlash(slash_count, b) + okpath

    content.replace(path,newpath,1)
    return content

def zeroStartingPort(content,basePort):
    payload_reqs =set()
    ports = ['080','0443','08080','04080']
    base_host = re.search("Host.+",content).group()
    for port in ports:
        new_host = base_host+ ':' +port
        new_content =  content.replace(base_host,new_host)
        payload_reqs.add(new_content)
        # print(new_content)

    new_host = base_host+ ':0' +basePort
    new_content = content.replace(base_host, new_host)
    payload_reqs.add(new_content)

    return payload_reqs

def changeHost2Ip(content,ip):
    new_host = "Host: "+ ip
    content = re.sub("Host: .+",new_host,content,1)
    return content

def deleteHostHeader(content):
    content = re.sub("Host: .+\n","",content,1)
    return content



def processContent(reqcontent,url,path,domain,ip,observed_hosts,okpaths,basePort):
    payload_req_contents = set()

    if "POST" in reqcontent[:10]:
            payload_req_contents.add(lowerCasePost(reqcontent,url))
    payload_req_contents.add(changeHost2Ip(reqcontent,ip))
    payload_req_contents.add(deleteHostHeader(reqcontent))
    payload_req_contents.update(absoluteUrl(reqcontent=reqcontent,observed_hosts=observed_hosts,url=url,host=domain,path=path))
    payload_req_contents.update(zeroStartingPort(reqcontent,basePort))
    if  okpaths:
        okpath = random.choice(list(okpaths))
        payload_req_contents.add(tabHttp1(reqcontent,path,okpath))

    return  payload_req_contents
