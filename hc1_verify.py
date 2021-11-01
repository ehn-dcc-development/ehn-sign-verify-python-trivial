#!env python3.8

import argparse
import json
import urllib.request
import sys
import zlib
import re
from base64 import b64decode, b64encode
from datetime import date, datetime

import cbor2
from binascii import unhexlify, hexlify

from base45 import b45decode
from cose.algorithms import Es256
from cose.keys.curves import P256
from cose.algorithms import Es256, EdDSA, Ps256
from cose.headers import KID, Algorithm
from cose.keys import CoseKey
from cose.keys.keyparam import KpAlg, EC2KpX, EC2KpY, EC2KpCurve, RSAKpE, RSAKpN
from cose.keys.keyparam import KpKty
from cose.keys.keytype import KtyEC2, KtyRSA
from cose.messages import CoseMessage
from cryptography import x509
from cryptography.utils import int_to_bytes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

DEFAULT_TRUST_URL = 'https://verifier-api.coronacheck.nl/v4/verifier/public_keys'
DEFAULT_TRUST_UK_URL = 'https://covid-status.service.nhsx.nhs.uk/pubkeys/keys.json'

def add_kid(kid_b64, key_b64):
        kid = b64decode(kid_b64)
        asn1data = b64decode(key_b64)

        pub = serialization.load_der_public_key(asn1data)
        if (isinstance(pub, RSAPublicKey)):
              kids[kid_b64] = CoseKey.from_dict(
               {   
                    KpKty: KtyRSA,
                    KpAlg: Ps256,  # RSSASSA-PSS-with-SHA-256-and-MFG1
                    RSAKpE: int_to_bytes(pub.public_numbers().e),
                    RSAKpN: int_to_bytes(pub.public_numbers().n)
               })
        elif (isinstance(pub, EllipticCurvePublicKey)):
              kids[kid_b64] = CoseKey.from_dict(
               {
                    KpKty: KtyEC2,
                    EC2KpCurve: P256,  # Ought o be pk.curve - but the two libs clash
                    KpAlg: Es256,  # ecdsa-with-SHA256
                    EC2KpX: pub.public_numbers().x.to_bytes(32, byteorder="big"),
                    EC2KpY: pub.public_numbers().y.to_bytes(32, byteorder="big")
               })
        else:
              print(f"Skipping unexpected/unknown key type (keyid={kid_b64}, {pub.__class__.__name__}).",  file=sys.stderr)


def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""

    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    raise TypeError ("Type %s not serializable" % type(obj))


parser = argparse.ArgumentParser(
    description="Parse and validate a base45/zlib/cose/cbor QR."
)
parser.add_argument(
    "-B", "--base64", action="store_true", help="Use base64 instead of base45"
)
parser.add_argument(
    "-b", "--skip-base45", action="store_true", help="Skip base45 decoding"
)
parser.add_argument(
    "-A", "--noanon", action="store_true", help="Do not anonymise"
)
parser.add_argument(
    "-z", "--skip-zlib", action="store_true", help="Skip zlib decompression"
)
parser.add_argument(
    "-X", "--xy", action="store", help="X,Y (comma separated, in lieu of cert)"
)
parser.add_argument(
    "-K", "--ignore-kid", action="store_true", help="Do not verify the KID."
)
parser.add_argument(
    "-k", "--kid", action="store", help="Specify the KID as an 8 byte hex value."
)
parser.add_argument(
    "-U", "--use-verifier", action="store_true", 
    help="Use default trusted keys (Dutch set; from the eHealth network): " + DEFAULT_TRUST_URL
)
parser.add_argument(
    "-G", "--use-uk-verifier", action="store_true", 
    help="Use default trusted keys from the UK: " + DEFAULT_TRUST_UK_URL
)
parser.add_argument(
    "-u", "--use-verifier-url", action="store", help="Use specific URL for trusted publick_keys"
)
parser.add_argument(
    "-i",
    "--ignore-signature",
    action="store_true",
    help="Ignore the signature, do not validate",
)
parser.add_argument(
    "-c",
    "--skip-cbor",
    action="store_true",
    help="Skip CBOR unpacking (accept any UTF8)",
)
parser.add_argument(
    "-C",
    "--skip-claim",
    action="store_true",
    help="Skip health claim unpacking",
)
parser.add_argument(
    "-p",
    "--prettyprint-json",
    action="store_true",
    help="Pretty print and sort the JSON. Will output UTF-8 as is (none pretty print will escape any UTF8).",
)
parser.add_argument(
    "cert", help="Certificate to validate against", default="dsc-worker.pem", nargs="?"
)
parser.add_argument(
    "-v", "--verbose", action="count", help="Verbose outout"
)
args = parser.parse_args()

cin = sys.stdin.buffer.read()

if args.base64:
    cin = b64decode(cin.decode("ASCII"))
else:
    if not args.skip_base45:
        cin = cin.decode("ASCII")

        if cin.startswith('HC1'):
              cin = cin[3:]
              if cin.startswith(':'):
                  cin = cin[1:]

        cin = b45decode(cin)

if not args.skip_zlib:
    if (cin[0] == 0x78):
       cin = zlib.decompress(cin)

decoded = CoseMessage.decode(cin)

kids = {}
keyid = None
key = None

if args.kid:
    keyid = bytes.fromhex(args.kid)

if args.xy:
    x, y = [bytes.fromhex(val) for val in args.xy.split(",")]
    key = CoseKey.from_dict({
                    KpKty: KtyEC2,
                    EC2KpCurve: P256,  # Ought o be pk.curve - but the two libs clash
                    KpAlg: Es256,  # ecdsa-with-SHA256
                    EC2KpX: x,
                    EC2KpY: y
    })
    if not args.ignore_kid and keyid:
        kids[b64encode(keyid).decode('ASCII')] = key

elif args.use_verifier or args.use_verifier_url:
    if args.ignore_signature:
      print("Flag --ignore-signature not compatible with trusted URL check", file=sys.stderr)
      sys.exit(1)
    if args.use_uk_verifier:
      print("Flag for UK verifier not compatible with trusted URL/EU-DCC check", file=sys.stderr)
      sys.exit(1)

    url = DEFAULT_TRUST_URL
    if args.use_verifier_url:
       url = args.use_verifier_url
    response = urllib.request.urlopen(url)
    pkg = json.loads(response.read())
    payload = b64decode(pkg['payload'])
    trustlist = json.loads(payload)
    eulist = trustlist['eu_keys']
    for kid_b64 in eulist:
        add_kid(kid_b64,eulist[kid_b64][0]['subjectPk'])

elif args.use_uk_verifier:
    url = DEFAULT_TRUST_UK_URL
    response = urllib.request.urlopen(url)
    uklist = json.loads(response.read())
    for e in uklist:
       add_kid(e['kid'], e['publicKey'])

else:
  if not args.ignore_signature:
    try:
        with open(args.cert, "rb") as file:
            pem = file.read()
        cert = x509.load_pem_x509_certificate(pem)
        pub = cert.public_key().public_numbers()
    except OSError as err:
        print(f"Unable to load certificate from '{args.cert}' file: {err.strerror}", file=sys.stderr)
        sys.exit(1)

    fingerprint = cert.fingerprint(hashes.SHA256())
    # keyid = fingerprint[-8:]
    keyid = fingerprint[0:8]
    keyid_b64 = b64encode(keyid).decode('ASCII')

    kids[keyid_b64] = CoseKey.from_dict(
               {
                    KpKty: KtyEC2,
                    EC2KpCurve: P256,  # Ought o be pk.curve - but the two libs clash
                    KpAlg: Es256,  # ecdsa-with-SHA256
                    EC2KpX: pub.x.to_bytes(32, byteorder="big"),
                    EC2KpY: pub.y.to_bytes(32, byteorder="big")
               }
    )

given_kid = None
if KID in decoded.phdr.keys():
   given_kid = decoded.phdr[KID]
else:
   given_kid = decoded.uhdr[KID]
   if args.verbose:
       print("KID in the unprotected header.", file=sys.stderr)

given_kid_b64 = b64encode(given_kid).decode('ASCII')
print(f"Signature           : {given_kid_b64} @ {decoded.phdr[Algorithm].fullname}")

if not args.ignore_signature:
    if not args.ignore_kid:
        if not given_kid_b64 in kids:
            print(f"KeyID is unknown (kid={given_kid_b64}) -- cannot verify.", file=sys.stderr)
            sys.exit(1)
        key  = kids[given_kid_b64]

    decoded.key = key
    if not decoded.verify_signature():
        print(f"Signature invalid (kid={given_kid_b64})", file=sys.stderr)
        sys.exit(1)

    if args.verbose:
        print(f"Correct signature againt known key (kid={given_kid_b64})", file=sys.stderr)
else:
    print("Warning: signature not validated", file=sys.stderr)
   
payload = decoded.payload

if not args.skip_cbor:
    payload = cbor2.loads(payload)
    if not args.skip_claim:
        claim_names = { 1 : "Issuer", 6: "Issued At", 4: "Experation time", -260 : "Health claims" }
        for k in payload:
          if k != -260:
            n = f'Claim {k} (unknown)'
            if k in claim_names:
               n = claim_names[k]
            print(f'{n:20}: {payload[k]}')
        # payload = cbor2.loads(payload[-260][1])
        payload = payload[-260][1]
        n = 'Health payload'
        print(f'{n:20}: ',end="")

    if not args.noanon:
        if 'dob' in payload:
           payload['dob'] = re.sub(r'\d{1}','X', payload['dob'])
        if 'nam' in payload:
           for k in payload['nam'].keys():
              # Handle accented chars somewhat graceful (but capitals will leak a bit).
              payload['nam'][k] = payload['nam'][k].encode("ascii","replace").decode('ascii')
              payload['nam'][k] = re.sub(r'[A-Z]{1}','X', payload['nam'][k])
              payload['nam'][k] = re.sub(r'[a-z\?]{1}','x', payload['nam'][k])
    if args.prettyprint_json:
        payload = json.dumps(payload, indent=4, sort_keys=True, default=json_serial, ensure_ascii=False)
    else:
        payload = json.dumps(payload, default=json_serial)
    if not args.noanon:
        payload = re.sub('URN:UV?CI:01:(\w+):\w+','URN:UCI:01:\g<1>:......', payload, flags=re.IGNORECASE)
    print(payload)
    sys.exit(0)

sys.stdout.buffer.write(payload)
sys.exit(0)

