import winreg
import ctypes
import requests
import base64
import json
from urllib.parse import urlparse
import time

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
        
if __name__=="__main__":
    b = setproxy(0)
    b.pac_off()