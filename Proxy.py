# -*- coding: utf-8 -*-

from __future__ import unicode_literals, print_function
import socket, sys, traceback, threading, time
import ssl
from Cert import CertUtility
import requests
import json, base64
from io import BytesIO
import zlib

proxies = {'http': None, 'https': None, "sock5":None}
mutex = threading.Lock()
CertUtil = CertUtility('Boxpaper', 'selfsigned.crt', 'certs')

proxyUrl = ""#写自己的！！！
MAX_HEADER_SIZE = 10086
RECV_SIZE = 512

def deflate(data):
    try:
        return zlib.decompress(data, -zlib.MAX_WBITS)
    except zlib.error:
        return zlib.decompress(data)
def getHeader(string):
    string=string.replace("\r","")
    headers={}
    for line in string.split("\n")[1:]:
        headers[line.split(":")[0].strip()] = (':'.join(line.split(":")[1:])).strip()
    return string[0:string.find(" ")],headers

def splitHeader(request):
    data = request.getvalue()
    headers = data.split(b"\r\n\r\n")[0].decode()
    body = b'\r\n\r\n'.join(data.split(b"\r\n\r\n")[1:])
    return headers,body

def transHost(raw_host):
    # 将raw_host解析为host和port
    for i in range(len(raw_host)): 
        if raw_host[i] == ":" : return raw_host[:i].strip(), int(raw_host[i+1:])
    else : return raw_host.strip(), 80


def thread_proxy(client):
    # 分离和分析请求头
    request = BytesIO()
    while True:
        try:
            data = client.recv(RECV_SIZE)
            request.write(data)
        except Exception:
            break

    header, body = splitHeader(request)
    
    method, requestHeader = getHeader(header)
    
    if not "Host" in requestHeader:
        print("无法解析的内容")
        client.close()
        return
    raw_host = requestHeader["Host"]
    host, port = transHost(raw_host)
    if method=="CONNECT":
        MakeHttps(host,client)
    else:
        if(isinstance(client,ssl.SSLSocket)):
            url = "https://" + requestHeader["Host"] +header.split(" ")[1]
        else:
            url = header.split(" ")[1]
        ForWardHttp(method,url,requestHeader,client, body)
    request.close()
    del request

def thread_server(myserver):
    #循环接收不同ip，端口信息
    while True:
        conn, addr = myserver.accept()
        conn.setblocking(0)
        conn.settimeout(1)
        thread_p = threading.Thread(target=thread_proxy, args=(conn,))
        thread_p.setDaemon(True)
        thread_p.start()

def ForWardHttp(method,url,requestHeader,client, body=None):
    print(method,url)
    if url == "/pac":
        client.sendall("HTTP/1.1 200 OK\r\nContent-Type: text/javascript; charset=UTF-8\r\n".encode())
        with open("pac.js","rb") as f:
            client.sendall(f.read())
        client.close()
        return 
    for i in ["Content-Encoding","Content-Length","Host","Accept-Encoding","Transfer-Encoding"]:
        for a in list(requestHeader.keys()):
            if i.upper() == a.upper():
                requestHeader.pop(a)
    if method == "GET":
        data = {
                "method": "GET",
                "url": url,
                "headers": base64.b64encode((json.dumps(requestHeader)).encode()).decode()
                }
        r = requests.post(proxyUrl,data=data,proxies=proxies,verify=False)
    
    elif method == "POST":
        if not body:
            body = "".encode()
        data = {
            "method": "POST",
            "url": url,
            "headers": base64.b64encode((json.dumps(requestHeader)).encode()).decode(),
            "data": base64.b64encode(body).decode()
            }
        r = requests.post(proxyUrl,data=data,proxies=proxies,verify=False)
    else:
        client.sendall("HTTP/1.1 400 Bad Request\r\n\r\n".encode())
        client.close()
        return 
    if r.status_code != 200:
        client.close()
        return
    result = json.loads(base64.b64decode(deflate(r.content)).decode())
    headers = ""
    rhed = json.loads(result["headers"])
    if isinstance(rhed,list):
        rhed = {}
    for i in ["Content-Encoding","Content-Length","Connection","Transfer-Encoding"]:
        for a in list(rhed.keys()):
            if i.upper() == a.upper():
                rhed.pop(a)
    for i in rhed:
        if i == "Cookies":
            for c in rhed[i].split("$")[:-1]:
                headers += "Set-Cookie" + ": " + c + "\n"
        elif i.upper() == 'CONTENT-TYPE':
            if rhed[i].find("charset")==-1:
                headers += "Content-Type: " + rhed[i] + "; charset=utf-8\n"
            else:
                headers += "Content-Type: " + rhed[i] + "\n"
        else:
            headers += i + ": " + rhed[i] + "\n"
    try:
        body = deflate(base64.b64decode(result['content']))
        print(result["status"])
        if result["status"] != "":
            client.sendall(("HTTP/1.1 %s\r\n%s\r\n"%(result["status"],headers)).encode())
        if body != b'':
            client.sendall(body)
    except Exception as e:
        print(e)
    client.close()
    
    #ss.close()
    
def MakeHttps(host,client):  
    client.send('HTTP/1.1 200 Connection Established\r\n\r\n'.encode())
    mutex.acquire()
    certfile = CertUtil.get_cert(host)
    mutex.release()
    client = ssl.wrap_socket(client,keyfile=certfile,certfile=certfile,server_side=True)
    thread_proxy(client)  


def main(_, port=8080):
    try:
        myserver = socket.socket()
        myserver.bind(('127.0.0.1', port))
        myserver.listen(1024)
        thread_s = threading.Thread(target=thread_server, args=(myserver,))
        thread_s.setDaemon(True)
        thread_s.start()
        while True: time.sleep(1)
    except KeyboardInterrupt:
        print("sys exit")
    finally:
        myserver.close()



if __name__ == '__main__':
    try:
        print("start server")
        main(*sys.argv)
    except Exception as e:
        print("error exit")
        traceback.print_exc()
    finally:
        print("end server")
    sys.exit(0)