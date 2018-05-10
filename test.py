import os
import ed25519
import struct
import time, tai64n
from pyblake2 import blake2b

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
SN_HASHKEY = "Bill Gates never said that 640K ought to be enough for anybody!!"
#[/] The SigNote's Serial Number (BLAKE2b 64-byte Hash of Initial Data)

def sn__generate_init():
  #Version Header
  out = [struct.pack( "!2sI", 'SN', 1)]
  # Start init section
  out += [struct.pack( "!BBH", 0, 0, 256)]

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


snote = sn__generate_init()

print len(snote['data'])
print "SIGNATURE:", snote['signature']
print repr(snote['data'])
