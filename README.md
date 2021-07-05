# Trivial/rudimentary eHN-simplified implementation

Aligned with version 1.00 / 2021-4-14 of the spec:
	https://github.com/ehn-digital-green-development/hcert-spec/blob/main/hcert_spec.md

For round-trip testing of ```hc1_sign.py``` and ```hc1_verify.py``` take some
JSON, e.g. ```{ "Foo" : "Bar }```, CBOR package, COSE sign, compress and base45
convert it for use in a QR.

1. COSE sign
   1. compact the JSON into CBOR
   1. wrap it into a payload (Health claim -260, add issuer/dates)
   1. sign and package as a COSE message
   1. ZLIB compress
   1. Base45 encode 
1. COSE verify     
   1. Base45 decode
   1. ZLIB decompress
   1. check the signature on the COSE message
   1. unpack the CBOR into JSON
   1. unpack the payload and extract the issuer and dates
   1. unpack the health claim and output as json.

### Test Steps

1. Generate the CSCA and DSC with ```./gen-csca-dsc.sh```	
1. Run the command: ```echo "{'A': 1234}" | python3.8 hc1_sign.py | python3.8 hc1_verify.py```
1. You should see the output: ```{"A": 1234}```

```echo '{ "Foo":1, "Bar":{ "Field1": "a value",   "integer":1212112121 }}' | python3.8 hc1_sign.py | python3.8 hc1_verify.py prettyprint-json```

Which should output:

```
{
    "Foo": 1, 
    "Bar": {
        "Field1": "a value", 
        "integer": 1212112121
   }
}
```

# Testing COSE from Austrian website

Testing against the AT cases:

1. Fetch the Base64 from https://dev.a-sit.at/certservice
1. Remove the first 2 bytes and do

   ```pbpaste| sed -e 's/^00//' | python3.8 hc1_verify.py --base64 --ignore-signature --cbor```

# Verify using Docker
1. Build doing e.g.: ```docker build . -t verify``` 
2. Verify from buffer: ```pbpaste | docker run -i verify -i -p```