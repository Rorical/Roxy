# -*- coding: utf-8 -*-

import OpenSSL
import threading
import sys
import hashlib
import time
import os
import random
import glob

class CertUtility(object):
    """Cert Utility module, based on mitmproxy"""

    def __init__(self, vendor, filename, dirname):
        self.ca_vendor = vendor
        self.ca_keyfile = filename
        self.ca_thumbprint = ''
        self.ca_certdir = dirname
        self.ca_digest = 'sha1' if sys.platform == 'win32' and sys.getwindowsversion() < (6,) else 'sha256'
        self.ca_lock = threading.Lock()
    def get_certificate_san(x509cert):
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
        capath = os.path.join(os.path.dirname(os.path.abspath(__file__)), self.ca_keyfile)
        certdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), self.ca_certdir)
        if not os.path.exists(capath):
            if os.path.exists(certdir):
                any(os.remove(x) for x in glob.glob(certdir+'/*.crt')+glob.glob(certdir+'/.*.crt'))
            if os.name == 'nt':
                try:
                    self.remove_ca(self.ca_vendor)
                except Exception as e:
                    print('self.remove_ca failed: %r', e)
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