#!env python3.8
import sys
import zlib
import argparse
import json
import cbor2
from base64 import b64encode


from base45 import b45encode
from cose.algorithms import Es256
from cose.curves import P256
from cose.algorithms import Es256, EdDSA
from cose.keys.keyparam import KpKty, KpAlg, EC2KpD, EC2KpX, EC2KpY, EC2KpCurve
from cose.headers import Algorithm, KID
from cose.keys import CoseKey
from cose.keys.keyparam import KpAlg, EC2KpD, EC2KpCurve
from cose.keys.keyparam import KpKty
from cose.keys.keytype import KtyEC2
from cose.messages import Sign1Message
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key

parser = argparse.ArgumentParser(description="Sign, B45 and compress a CBOR")
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
    "-c",
    "--skip-cbor",
    action="store_true",
    help="Skip encoding the input with CBOR first (i.e. accept plain UTF-8)",
)
parser.add_argument(
    "keyfile",
    default="dsc-worker.key",
    nargs="?",
    help="The private key to sign the request with; using <dsc-worker.key> as the default. PEM format.",
)
parser.add_argument(
    "certfile",
    default="dsc-worker.pem",
    nargs="?",
    help="The certificate whose 'KeyID to include'; using <dsc-worker.pem> as the default. PEM format.",
)
args = parser.parse_args()

payload = sys.stdin.buffer.read()

if not args.skip_cbor:
    payload = json.loads(payload.decode("utf-8"))
    payload = cbor2.dumps(payload)

# Note - we only need the public key for the KeyID calculation - we're not actually using it.
#
with open(args.certfile, "rb") as file:
    pem = file.read()
cert = x509.load_pem_x509_certificate(pem)
fingerprint = cert.fingerprint(hashes.SHA256())
keyid = fingerprint[0:8]

# Read in the private key that we use to actually sign this
#
with open(args.keyfile, "rb") as file:
    pem = file.read()
keyfile = load_pem_private_key(pem, password=None)
priv = keyfile.private_numbers().private_value.to_bytes(32, byteorder="big")

# Prepare a message to sign; specifying algorithm and keyid
# that we (will) use
#
msg = Sign1Message(phdr={Algorithm: Es256, KID: keyid}, payload=payload)

# Create the signing key - use ecdsa-with-SHA256
# and NIST P256 / secp256r1
#
cose_key = {
    KpKty: KtyEC2,
    KpAlg: Es256,  # ecdsa-with-SHA256
    EC2KpCurve: P256,  # Ought to be pk.curve - but the two libs clash
    EC2KpD: priv,
}

# Encode the message (which includes signing)
#
msg.key = CoseKey.from_dict(cose_key)
out = msg.encode()

# Compress with ZLIB
#
if not args.skip_zlib:
    out = zlib.compress(out, 9)

# And base45 encode the result
#
if args.base64:
    out = b64encode(out)
else:
   if not args.skip_base45:
      out = b'HC1' + b45encode(out).encode('ascii')

sys.stdout.buffer.write(out)
