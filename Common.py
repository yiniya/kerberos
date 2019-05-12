import sys
import hashlib
sys.path.append("Enc_Dec")
import DES
import rsa2


def Des(str,key,mode):
    if mode == 0:#加密
        text = str
        length = len(text)
        if length%4 > 0 :
            text = text + (4 - (length % 4)) * " "
            length = len(text)
        finalRes = ""
        for i in range(int(length / 4)):
            tempText = [text[j] for j in range(i * 4, i * 4 + 4)]
            finalRes = finalRes + DES.Des(tempText, key)
        #print(finalRes)
        return finalRes

    elif mode == 1:#解密
        text = str
        length = len(text)
        finalRes = ""
        for i in range(int(length / 16)):
            tempText = text[i * 16: i * 16 + 16]
            finalRes = finalRes + DES.DeDes(tempText, key)
        #print(finalRes)
        return finalRes
    else:#错误调用
        return None

def Hash_MD5(inString):
    #outString = ''
    h = hashlib.md5()
    h.update(inString.encode(encoding='utf-8'))
    return h.hexdigest()

#字符串转unicode2进制序列 inString：输入为字符串 返回值：string类型的二进制序列长度为 len(inString)*16
def Char2Binary(inString):
    temp = []
    for i in range(len(inString)):
        temp.append(ord(inString[i]))
    #print(temp)
    temp.reverse()
    output = []
    for i in range(len(temp) * 16):
        output.append((temp[int(i / 16)] >> (i % 16)) & 1)  # 左移1bit
    output.reverse()
    outString = ''
    for i in range(len(output)):
        outString += str(output[i])
    return outString

#unicode码对应的二进制序列转换成对应的Unicode码对应的字符串
def Binary2Char(inString):
    out = []
    temp = 0
    inString = inString[::-1]
    for i in range(len(inString)):
        temp = temp | (int(inString[i]) << (i % 16))
        if i % 16 == 15:
            out.append(temp)
            temp = 0
    out.reverse()
    outString = ""
    for i in range(len(out)):
        outString = outString + chr(out[i])
    return outString

#可见的字符串序列转换成对应的ascii码的二进制序列
def Ascii2Binary(inString):
    temp = []
    for i in range(len(inString)):
        temp.append(ord(inString[i]))
    #print(temp)
    temp.reverse()
    output = []
    for i in range(len(temp) * 8):
        output.append((temp[int(i / 8)] >> (i % 8)) & 1)  # 左移1bit
    output.reverse()
    outString = ''
    for i in range(len(output)):
        outString += str(output[i])
    return outString

#ASCII码对应的二进制序列字符串转换成可见的字符串
def Binary2Ascii(inString):
    out = []
    temp = 0
    inString = inString[::-1]
    for i in range(len(inString)):
        temp = temp | (int(inString[i]) << (i % 8))
        if i % 8 == 7:
            out.append(temp)
            temp = 0
    out.reverse()
    outString = ""
    for i in range(len(out)):
        outString = outString + chr(out[i])
    return outString

def qianming(name):

    m = Hash_MD5(name)
    (n, e, d) = rsa2.Build_key()
    C = rsa2.encrypt(m, e, n)
    d = hex(d)
    n= hex(n)
    return C,d,n

def yanzheng(M,C,key):#RSA验证

    d=key[0:258]
    d=int(d,16)
    n=key[258:]

    n=int(n,16)
    print(M)
    print(M.encode("utf-8"))
    m =Hash_MD5(M)
    print(m)
    M=rsa2.decrypt(C,d,n)
    print(M)
    if M==m:
        return True
    else:
        return False
'''m = "我是yyz,他是zwj"
length = len(m)

c = Des(m,'********',0)
print(c)
result = Des(c,"********",1)
print(result)'''
