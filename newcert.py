# -*- coding: utf-8 -*-
CERT_FILE = "selfsigned.crt"
from OpenSSL import crypto
def create_self_signed_cert():

    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 1024)

    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = "CN"
    cert.get_subject().ST = "Internet"
    cert.get_subject().L = "Cernet"
    cert.get_subject().O = "Boxpaper"
    cert.get_subject().OU = "Boxpaper"
    cert.get_subject().CN = "Boxpaper"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(20*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha1')

    with open(CERT_FILE, "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode())
        f.write("\n")
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode())

create_self_signed_cert()