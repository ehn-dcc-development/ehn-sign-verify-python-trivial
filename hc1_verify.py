#!env python3.8

import argparse
import json
import sys
import zlib
from base64 import b64decode

import cbor2
from binascii import unhexlify, hexlify

from base45 import b45decode
from cose.algorithms import Es256
from cose.curves import P256
from cose.algorithms import Es256, EdDSA
from cose.headers import KID
from cose.keys import CoseKey
from cose.keys.keyparam import KpAlg, EC2KpX, EC2KpY, EC2KpCurve
from cose.keys.keyparam import KpKty
from cose.keys.keytype import KtyEC2
from cose.messages import CoseMessage
from cryptography import x509
from cryptography.hazmat.primitives import hashes

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
    "-z", "--skip-zlib", action="store_true", help="Skip zlib decompression"
)
parser.add_argument(
    "-X", "--xy", action="store", help="X,Y (comma separated, in lieu of cert)"
)
parser.add_argument(
    "-K", "--ignore-kid", action="store_true", help="Do not verify the KID"
)
parser.add_argument(
    "-k", "--kid", action="store", help="Specify the KID as an 8 byte hex value."
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
    help="Pretty print and sort the JSON",
)
parser.add_argument(
    "cert", help="Certificate to validate against", default="dsc-worker.pem", nargs="?"
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

if not args.ignore_signature:
    with open(args.cert, "rb") as file:
        pem = file.read()
    if args.xy:
        x, y = [bytes.fromhex(val) for val in args.xy.split(",")]
        keyid = None
    else:
        cert = x509.load_pem_x509_certificate(pem)
        pub = cert.public_key().public_numbers()

        fingerprint = cert.fingerprint(hashes.SHA256())
        # keyid = fingerprint[-8:]
        keyid = fingerprint[0:8]

        x = pub.x.to_bytes(32, byteorder="big")
        y = pub.y.to_bytes(32, byteorder="big")

    if args.kid:
        keyid = bytes.fromhex(args.kid)

    if not args.ignore_kid:
        given_kid = None
        if KID in decoded.phdr.keys():
            given_kid = decoded.phdr[KID]
        else:
            given_kid = decoded.uhdr[KID]

        if given_kid != keyid:
            raise Exception(
                "KeyID is unknown (expected %s, got %s) -- cannot verify."
                % (hexlify(keyid), hexlify(given_kid))
            )

    decoded.key = CoseKey.from_dict(
        {
            KpKty: KtyEC2,
            EC2KpCurve: P256,  # Ought o be pk.curve - but the two libs clash
            KpAlg: Es256,  # ecdsa-with-SHA256
            EC2KpX: x,
            EC2KpY: y,
        }
    )
    if not decoded.verify_signature():
        raise Exception("faulty sig")

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

    if args.prettyprint_json:
        payload = json.dumps(payload, indent=4, sort_keys=True)
    else:
        payload = json.dumps(payload)
    print(payload)
    sys.exit(0)

sys.stdout.buffer.write(payload)
