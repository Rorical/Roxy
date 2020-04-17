import OpenSSL
import threading
import sys
import hashlib
import time
import os
import random
import glob
import socket
import ssl
import requests
import json
import base64
from io import BytesIO
import zlib
import re
import atexit
from signal import signal, SIGTERM
import configparser
import winreg
import ctypes
from urllib.parse import urlparse
import time

requests.packages.urllib3.disable_warnings()

class setproxy():
    INTERNET_SETTINGS = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
    'Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings',
    0, winreg.KEY_ALL_ACCESS)
    INTERNET_OPTION_REFRESH = 37
    INTERNET_OPTION_SETTINGS_CHANGED = 39
    internet_set_option = ctypes.windll.Wininet.InternetSetOptionW
    def __init__(self,port):
        self.port = port
    def creat_key(self,name, value,mytype):
        winreg.CreateKey(self.INTERNET_SETTINGS, name)
        winreg.SetValueEx(self.INTERNET_SETTINGS, name, 0, mytype, value)
    def del_key(self,name):
        winreg.DeleteValue(self.INTERNET_SETTINGS,name)
    #稍加改造简书的https://www.jianshu.com/p/6862d35e2855

    def pac_on(self):
        self.creat_key('AutoConfigURL', u'http://localhost:'+str(self.port)+"/pac",1)
        self.internet_set_option(0, self.INTERNET_OPTION_REFRESH, 0, 0)
        self.internet_set_option(0,self.INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)

    def pac_off(self):
        try:
            self.del_key("AutoConfigURL")
            self.del_key("AutoConfigURL")
        except:
            time.sleep(0.5)
        self.internet_set_option(0, self.INTERNET_OPTION_REFRESH, 0, 0)
        self.internet_set_option(0,self.INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)

class CertUtility(object):
    """Cert Utility module, based on mitmproxy"""
    def __init__(self, vendor, filename, dirname):
        self.ca_vendor = vendor
        self.ca_keyfile = filename
        self.ca_thumbprint = ''
        self.ca_certdir = dirname
        self.ca_digest = 'sha1' if sys.platform == 'win32' and sys.getwindowsversion() < (6,) else 'sha256'
        self.ca_lock = threading.Lock()
    def get_certificate_san(self,x509cert):
        san = ''
        ext_count = x509cert.get_extension_count()
        for i in range(0, ext_count):
            ext = x509cert.get_extension(i)
            if 'subjectAltName' in str(ext.get_short_name()):
                san = ext.__str__()
        return san
    def create_ca(self):
        key = OpenSSL.crypto.PKey()
        key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
        req = OpenSSL.crypto.X509Req()
        subj = req.get_subject()
        subj.countryName = 'CN'
        subj.stateOrProvinceName = 'Internet'
        subj.localityName = 'Cernet'
        subj.organizationName = self.ca_vendor
        subj.organizationalUnitName = self.ca_vendor
        subj.commonName = self.ca_vendor
        req.set_pubkey(key)
        req.sign(key, self.ca_digest)
        ca = OpenSSL.crypto.X509()
        ca.set_serial_number(0)
        ca.gmtime_adj_notBefore(0)
        ca.gmtime_adj_notAfter(24 * 60 * 60 * 3652)
        ca.set_issuer(req.get_subject())
        ca.set_subject(req.get_subject())
        ca.set_pubkey(req.get_pubkey())
        ca.sign(key, 'sha1')
        
        return key, ca

    def dump_ca(self):
        key, ca = self.create_ca()
        with open(self.ca_keyfile, 'wb') as fp:
            fp.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, ca))
            fp.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key))

    def get_cert_serial_number(self, commonname):
        assert self.ca_thumbprint
        saltname = '%s|%s' % (self.ca_thumbprint, commonname)
        return int(hashlib.md5(saltname.encode('utf-8')).hexdigest(), 16)

    def _get_cert(self, commonname, sans=()):
        with open(self.ca_keyfile, 'rb') as fp:
            content = fp.read()
            key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, content)
            ca = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, content)

        pkey = OpenSSL.crypto.PKey()
        pkey.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

        req = OpenSSL.crypto.X509Req()
        subj = req.get_subject()
        subj.countryName = 'CN'
        subj.stateOrProvinceName = 'Internet'
        subj.localityName = 'Cernet'
        subj.organizationalUnitName = self.ca_vendor
        if commonname[0] == '.':
            subj.commonName = '*' + commonname
            subj.organizationName = '*' + commonname
            sans = ['*'+commonname] + [x for x in sans if x != '*'+commonname]
        else:
            subj.commonName = commonname
            subj.organizationName = commonname
            sans = [commonname] + [x for x in sans if x != commonname]
        #req.add_extensions([OpenSSL.crypto.X509Extension(b'subjectAltName', True, ', '.join('DNS: %s' % x for x in sans)).encode()])
        req.set_pubkey(pkey)
        req.sign(pkey, self.ca_digest)

        cert = OpenSSL.crypto.X509()
        cert.set_version(2)
        try:
            cert.set_serial_number(self.get_cert_serial_number(commonname))
        except OpenSSL.SSL.Error:
            cert.set_serial_number(int(time.time()*1000))
        cert.gmtime_adj_notBefore(-600) #avoid crt time error warning
        cert.gmtime_adj_notAfter(60 * 60 * 24 * 3652)
        cert.set_issuer(ca.get_subject())
        cert.set_subject(req.get_subject())
        cert.add_extensions([
            OpenSSL.crypto.X509Extension(
                b"keyUsage", True,
                b"Digital Signature, Non Repudiation, Key Encipherment"),
            OpenSSL.crypto.X509Extension(
                b"basicConstraints", False, b"CA:FALSE"),
            OpenSSL.crypto.X509Extension(
                b'extendedKeyUsage', False, b'serverAuth, clientAuth'),
            OpenSSL.crypto.X509Extension(
                b"subjectAltName", False, (', '.join('DNS: %s' % x for x in sans)).encode()
                )
            ])
        cert.set_pubkey(req.get_pubkey())
        if commonname[0] == '.':
            sans = ['*'+commonname] + [s for s in sans if s != '*'+commonname]
        else:
            sans = [commonname] + [s for s in sans if s != commonname]
        #cert.add_extensions([OpenSSL.crypto.X509Extension(b'subjectAltName', True, ', '.join('DNS: %s' % x for x in sans))])
        cert.sign(key, self.ca_digest)
        
        certfile = os.path.join(self.ca_certdir, commonname + '.crt')
        with open(certfile, 'wb') as fp:
            fp.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))
            fp.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey))
        return certfile

    def get_cert(self, commonname, sans=()):
        self.check_ca()
        if commonname.count('.') >= 2 and [len(x) for x in reversed(commonname.split('.'))] > [2, 4]:
            commonname = '.'+commonname.partition('.')[-1]
        certfile = os.path.join(self.ca_certdir, commonname + '.crt')
        if os.path.exists(certfile):
            return certfile
        elif OpenSSL is None:
            return self.ca_keyfile
        else:
            with self.ca_lock:
                if os.path.exists(certfile):
                    return certfile
                return self._get_cert(commonname, sans)

    def check_ca(self):
        #Check CA exists
        capath = self.ca_keyfile
        certdir = self.ca_certdir
        if not os.path.exists(capath):
            if os.path.exists(certdir):
                any(os.remove(x) for x in glob.glob(certdir+'/*.crt')+glob.glob(certdir+'/.*.crt'))
            self.dump_ca()
        with open(capath, 'rb') as fp:
            self.ca_thumbprint = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, fp.read()).digest('sha1')
        #Check Certs
        certfiles = glob.glob(certdir+'/*.crt')+glob.glob(certdir+'/.*.crt')
        if certfiles:
            filename = random.choice(certfiles)
            commonname = os.path.splitext(os.path.basename(filename))[0]
            with open(filename, 'rb') as fp:
                serial_number = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, fp.read()).get_serial_number()
            if serial_number != self.get_cert_serial_number(commonname):
                any(os.remove(x) for x in certfiles)
        #Check Certs Dir
        if not os.path.exists(certdir):
            os.makedirs(certdir)

class Proxy(object): #basic functions
    class proxyReq():
        def popheaders(self,header,pops):
            for i in pops:
                for a in list(header.keys()):
                    if i.upper() == a.upper():
                        header.pop(a)
            return header
        def __init__(self,method,url,headers,data=None):
            self.method = method
            self.url = url
            self.headers = json.dumps(self.popheaders(headers,["Content-Encoding","Content-Length","Host","Accept-Encoding","Transfer-Encoding"]))
            self.data = base64.b64encode(data) if data else b''
        def get(self):
            return dict(vars(self).items())
    class proxyRes():
        def popheaders(self,header,pops):
            for i in pops:
                for a in list(header.keys()):
                    if i.upper() == a.upper():
                        header.pop(a)
            return header
        def __init__(self,content):
            resjson = json.loads(base64.b64decode(self.inflate(content)).decode())
            preheader = resjson["headers"]
            self.status = resjson["status"]
            if isinstance(preheader,list):
                preheader = {}
            preheader = self.popheaders(preheader,["Content-Encoding","Content-Length","Connection","Transfer-Encoding"])
            self.headers = self.parsedictheader(preheader)
            self.content = self.inflate(base64.b64decode(resjson['content']))
        def parsedictheader(self,dicheader):
            headers = ""
            for i in dicheader:
                if i == "Cookies":
                    for c in dicheader[i].split("$")[:-1]:
                        headers += "Set-Cookie" + ": " + c + "\n"
                elif i.upper() == 'CONTENT-TYPE':
                    if dicheader[i].find("charset")==-1:
                        headers += "Content-Type: " + dicheader[i] + "; charset=utf-8\n"
                    else:
                        headers += "Content-Type: " + dicheader[i] + "\n"
                else:
                    headers += i + ": " + dicheader[i] + "\n"
            return headers
        def inflate(self,data):
            try:
                return zlib.decompress(data, -zlib.MAX_WBITS)
            except zlib.error:
                try:
                    return zlib.decompress(data)
                except Exception as e:
                    print("Failed to decompress data:",data)
                    return None
        def get(self):
            return dict(vars(self).items())

    def __init__(self,timeout,proxyUrl):
        self.timeout = timeout
        self.proxyUrl = proxyUrl
    def isip(self,h):
        p = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
        return True if p.match(h) else False
    def getheaders(self,heads):
        heads=heads.replace("\r","")
        headers={}
        for line in heads.split("\n")[1:]:
            headers[line.split(":")[0].strip()] = (':'.join(line.split(":")[1:])).strip()
        return heads[0:heads.find(" ")],headers
    def splitheaders(self,request):
        data = request.getvalue()
        headers = data.split(b"\r\n\r\n")[0].decode()
        body = b'\r\n\r\n'.join(data.split(b"\r\n\r\n")[1:])
        return headers,body
    def splithost(self,raw_host):
        for i in range(len(raw_host)): 
            if raw_host[i] == ":" : return raw_host[:i].strip(), int(raw_host[i+1:])
        else : return raw_host.strip(), None
    def postserver(self,data):
        return requests.post(self.proxyUrl,data=data,proxies={'http': None, 'https': None, "sock5":None},verify=False,timeout=int(self.timeout))

class Roxy(object): #main functions
    def __init__(self,configfile = "settings.ini"):
        self.mutex = threading.Lock()
        self.CertUtil = CertUtility('Boxpaper', 'selfsigned.crt', 'certs')
        self.CertUtil.get_cert("www.google.com")
        self.RECV_SIZE = 512
        self.namedicts = {"server":{"url":"https://ucrhvx616.tw01.horainwebs.top/","timeout":10},"client":{"port":8080}}#默认的参数，自动填充
        self.readconfig(configfile)
        self.functions = Proxy(self.server_timeout,self.server_url)
        self.proxySetting = setproxy(self.client_port)
        self.proxySetting.pac_on()
    def __del__(self):
        self.proxySetting.pac_off()
        print("Proxy Terminated")
        pass
    def readconfig(self,configfile = "settings.ini"):
        if os.path.exists(configfile):
            con = configparser.ConfigParser()
            con.read(configfile, encoding='utf-8')
            for i in self.namedicts:
                if i in con:
                    serversetting = dict(con.items(i))
                    for a in self.namedicts[i]:
                        if a in serversetting:
                            self.__dict__[i+"_"+a] = serversetting[a]
                        else:
                            self.__dict__[i+"_"+a] = self.namedicts[i][a]
                else:
                    for a in self.namedicts[i]:
                        self.__dict__[i+"_"+a] = self.namedicts[i][a]
        else:
            for i in self.namedicts:
                for a in self.namedicts[i]:
                    self.__dict__[i+"_"+a] = self.namedicts[i][a]
            self.writeconfig(configfile)
    def writeconfig(self,configfile = "settings.ini"):
        con = configparser.ConfigParser()
        for i in self.namedicts:
            con[i] = self.namedicts[i]
        with open(configfile, 'w') as f:
            con.write(f)
    def proxy(self,client):
        request = BytesIO()
        while True:
            try:
                data = client.recv(self.RECV_SIZE)
                request.write(data)
                if data == b"":
                    break
            except Exception:
                break
        header, body = self.functions.splitheaders(request)
        method, requestHeader = self.functions.getheaders(header)
        if not "Host" in requestHeader:
            print("Req has no host")
            client.close()
            return
        host, port = self.functions.splithost(requestHeader["Host"])
        if host == "localhost" or host == "127.0.0.1":
            client.sendall("HTTP/1.1 200 OK\r\nContent-Type: text/javascript; charset=UTF-8\r\n".encode())
            with open("pac.js","r") as f:
                client.sendall(f.read().replace("__Proxy_Addr__","PROXY 127.0.0.1:"+self.client_port).encode())
            client.close()
            return 
        if method=="CONNECT":
            self.MakeHttps(host,client)
        else:
            if(isinstance(client,ssl.SSLSocket)):
                url = "https://" + requestHeader["Host"]
                if port:
                    url += ":" + str(port)
                url += header.split(" ")[1]
            else:
                url = header.split(" ")[1]
            self.ForWardHttp(method,url,requestHeader,client,body)
        request.close()
        del request
    def MakeHttps(self,host,client):  
        client.send('HTTP/1.1 200 Connection Established\r\n\r\n'.encode())
        self.mutex.acquire()
        if self.functions.isip(host):
            certfile = self.CertUtil.get_cert("www.boxpaper.club")
        else:
            certfile = self.CertUtil.get_cert(host)
        try:
            client = ssl.wrap_socket(client,keyfile=certfile,certfile=certfile,server_side=True)
        except ssl.SSLError as err:
            print("SSL连接错误！请检测证书安装情况")
            print(err)
        self.mutex.release()
        self.proxy(client)
    def ForWardHttp(self,method,url,requestHeader,client, body=None):
        print(method,url)
        if url == "/pac":
           client.sendall("HTTP/1.1 200 OK\r\nContent-Type: text/javascript; charset=UTF-8\r\n".encode())
           with open("pac.js","rb") as f:
               client.sendall(f.read())
           client.close()
           return 
        reqobj = self.functions.proxyReq(method,url,requestHeader,body).get()
        try:
            if method == "GET":
                res = self.functions.postserver(reqobj)
            elif method == "HEAD":
                res = self.functions.postserver(reqobj)
            elif method == "OPTIONS":
                res = self.functions.postserver(reqobj)
            elif method == "POST":
                res = self.functions.postserver(reqobj)
            elif method == "PUT":
                res = self.functions.postserver(reqobj)
            else:
                client.sendall("HTTP/1.1 400 Bad Request\r\n\r\n".encode())
                client.close()
                return 
        except Exception as e:
            print(e)
            client.close()
            return
        resobj = self.functions.proxyRes(res.content).get()
        if resobj["status"] == "":
            client.close()
            return
        try:
            client.sendall(("HTTP/1.1 %s\r\n%s\r\n"%(resobj["status"],resobj["headers"])).encode())
            client.sendall(resobj["content"])
        except Exception as e:
            print(e)
        finally:
            client.close()
    def main(self):
        try:
            print("Proxy Started")
            proxyserver = socket.socket()
            proxyserver.bind(('127.0.0.1', int(self.client_port)))
            proxyserver.listen(1024)
            while True:
                conn, addr = proxyserver.accept()
                conn.setblocking(0)
                conn.settimeout(1)
                thread_p = threading.Thread(target=self.proxy, args=(conn,))
                thread_p.setDaemon(True)
                thread_p.start()
        finally:
            proxyserver.close()

r = Roxy()
r.main()
r.proxySetting.pac_off()