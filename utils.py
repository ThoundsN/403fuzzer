def findAllCharIndexesInString(s, ch):
    return [i for i, ltr in enumerate(s) if ltr == ch]

def generatedotdotSlash(count,payload):
    single = '/' + payload
    return single * count

def generatedotdotSlashEncoded(count,payload):
    single = '%25' + payload
    return single * count


def array2Str(array):
    s = ""
    for a in array:
        s += chr(a)
    return s