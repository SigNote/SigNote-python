import os
import ed25519
import struct
import time, tai64n
from pyblake2 import blake2b

from construct import Struct, Const, Int8ub, Bytes, Int16ub

_SN_VERSION = Struct(
  "magic" / Const(b"SN")
, "version" / Const(1, Int16ub)
)

_SN_SECTION_HEADER = Struct(
  "type" / Int8ub
 ,"flags" / Int8ub
 ,"length" / Int16ub
);

_SN_SECTION_INIT = Struct(
  "version" / _SN_VERSION
 ,"header" / Struct(
    "type" / Int8ub
    ,"flags" / Int8ub
    ,"length" / Const(248, Int16ub)
  )
 ,"isocode" / Bytes(3)
 ,"seqnum" / Bytes(13)
 #SN__DENOMINATION_FLAGS, SN__DENOMINATION, SN__DECIMALPLACE
 ,"denomination_flags" / Int8ub
 ,"denomination" / Int16ub
 ,"decimalplace" / Int8ub
 #SN__MINT_PK, SN__MINT_PK_CRSIG
 ,"mint_pk" / Bytes(32)
 ,"mint_pk_crsig" / Bytes(64)
 #nonce, hashkey
 ,"nonce" / Bytes(4)
 ,"hashkey" / Bytes(64)
 ,"signature" / Bytes(64)
);

'''
------------- 4-bytes / 32 bits -------------
+------------++-------------++--------------+
|SECTION TYPE||SECTION FLAGS||SECTION LENGTH|
|(UINT8=0xFF)||   (UINT8)   ||   (UINT16)   |
+------------++-------------++--------------+
------------ 16-bytes / 128 bits ------------
+------------------++-----------------------+
| TAI64N Timestamp ||     Random Nonce      |
|    (12 bytes)    ||       (UINT32)        |
+------------------++-----------------------+
------------ 32-bytes / 256-bits ------------
+-------------------------------------------+
|             SIGNER PUBLIC KEY             |
|             Ed25519(256-bits)             |
+-------------------------------------------+
------------ 64-bytes / 512-bits ------------
+-------------------------------------------+
|    Signature of file up to this point     |
|             Ed25519(512-bits)             |
+-------------------------------------------+
'''

_SN_SECTION_CHECKPOINT = Struct(
  "header" / Struct(
    "type" / Int8ub
    ,"flags" / Int8ub
    ,"length" / Const(112, Int16ub)
  )
 ,"timestamp" / Bytes(12)
 ,"nonce" / Bytes(4)
 ,"publickey" / Bytes(32)
 ,"checkpoint_sig" / Bytes(64)
)

_SIX_MONTH_IN_SECONDS = 15778463

'''
What we need for creating a test SigNote:

[X] Public/Private keypair for central reserve
[X] Public/Private keypair for mint
[X] Signature data from central reserve signing
'''

KEYPAIR__CENTRAL_RESERVE = ed25519.create_keypair()
KEYPAIR__CENTRAL_MINT = ed25519.create_keypair()

#sign the central mint with the central reserve root
SIGNATURE__CR_TO_CM = KEYPAIR__CENTRAL_RESERVE[0].sign(KEYPAIR__CENTRAL_MINT[1].to_bytes())
#print "SIGNATURE__CR_TO_CM length is", len(SIGNATURE__CR_TO_CM)

#
# let's sign a SigNote into existance
#

t_now = time.time()

#[X] Creation Time (TAI64N, 12-bytes)
SN__TIME_CREATION = tai64n.encode(t_now)
#[X] Spent at Time (TAI64N, 12-bytes)
SN__TIME_SPENTLIM = tai64n.encode(t_now + _SIX_MONTH_IN_SECONDS)
#[X] 3-letter Currency Code (ISO 4217, 3-bytes, Ex: JPY, USD)
SN__ISOCODE = "XTS" 
#[X] Currency Denomination (UINT16, Non-Zero)
SN__DENOMINATION = 10000
#[X] Sequential Identifier (13-bytes, all uppercase, a-z 0-9, asterisk 0x2A padded)
SN__SQNUMBER = '{seq:*<{fill}}'.format(seq='TS001', fill='13').upper()
#[X] Decimal place / subunit indicator position (UINT8, number of places from start of number, Ex: USD is 2, JPY is 0)
SN__DECIMALPLACE = 0
#[X] Currency Denomination Flags
SN__DENOMINATION_FLAGS = 0
#[X] Public key of Authorized Agent of a government's central reserve (Ed25519 key, 32-bytes)
SN__MINT_PK = KEYPAIR__CENTRAL_MINT[1].to_bytes()
#[X] Signature data from currency code trust root (government central reserve) authorizing Agent's public key (Ed25519 signature, 64-bytes)
SN__MINT_PK_CRSIG = SIGNATURE__CR_TO_CM
#[X] Nonce (UINT32)
SN_NONCE = os.urandom(4) #4 bytes = uint32
#[X] SigNote Hash Key String (64-Bytes) (Ex: "In God We Trust. Copyright The United States Federal Reserve")
SN_HASHKEY = 'Bill Gates has never said "640K ought to be enough for anybody!"'
#[/] The SigNote's Serial Number (BLAKE2b 64-byte Hash of Initial Data)

def sn__generate_init():
  out = []

  #Version Header
  out += [struct.pack( "!2sH", 'SN', 1)]
  # Start init section
  out += [struct.pack( "!BBH", 0, 0, 248)]

  # [ISO][SQNUM] = 128 bits
  out += [SN__ISOCODE, SN__SQNUMBER]

  # flags, deno, decimal = 32 bits
  out += [struct.pack( "!BHB", SN__DENOMINATION_FLAGS, SN__DENOMINATION, SN__DECIMALPLACE)]

  #trust root information = 768 bits
  out += [SN__MINT_PK, SN__MINT_PK_CRSIG]

  #SigNote Signature
  out += [SN_NONCE, SN_HASHKEY]

  data = ''.join( out )

  signature = blake2b(data=data, digest_size=64, key=SN_HASHKEY)

  return {"data": data + signature.digest(), "signature": signature.hexdigest()}


def sn__checkpoint_apply(blob, skpk):
  checkpoint = blob + _SN_SECTION_CHECKPOINT.build(dict(
      header=dict(type=0xFF, flags=0x0)
     ,timestamp="*"*12
     ,nonce=os.urandom(4)
     ,publickey=skpk[1].to_bytes()
     ,checkpoint_sig="\x00"*64
     ))

  signature = skpk[0].sign( checkpoint[:-64] )
  return checkpoint[:-64] + signature

snote = sn__generate_init()

print len(snote['data'])
print "SIGNATURE:", snote['signature']
print repr(snote['data'])

print _SN_SECTION_INIT.parse( snote['data'] )

print "CHECKPOINT"
print repr( sn__checkpoint_apply(snote['data'], KEYPAIR__CENTRAL_MINT) )

