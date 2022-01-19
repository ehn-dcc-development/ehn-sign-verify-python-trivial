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

### Decoding a barcode from production (i.e. a DCC in the wild)

     qrdecode photo.jpg | python3 ./hc1_verify.py -v -U -p

or

     qrdecode photo.jpg | python3 ./hc1_verify.py -v -i -p

The first will check against the Dutch copy of the eHealth trustlist; the second version, with the -i, will not check the actual signature. The typical output will look like:

```
Correct signature against known key (kid=3lTmAZX19GQ=)
Issuer              : NL
Experation time     : 1626966160
Issued At           : 1624546960
Health payload      : {
    "dob": "XXXX-XX-XX",
    "nam": {
        "fn": "xxx Xxxxx",
        "fnt": "XXX<XXXXX",
        "gn": "Xxxx Xxxxxx",
        "gnt": "XXXX<XXXXXX"
    },
    "v": [
        {
            "ci": "URN:UCI:01:NL:......#:",
            "co": "NL",
            "dn": 1,
            "dt": "2021-06-07",
            "is": "Ministry of Health Welfare and Sport",
            "ma": "ORG-100001417",
            "mp": "EU/1/20/1525",
            "sd": 1,
            "tg": "840539006",
            "vp": "J07BX03"
        }
    ],
    "ver": "1.3.0"
}
```

### Test Steps

1. Generate the CSCA and DSC with ```./gen-csca-dsc.sh```	
1. Run the command: ```echo '{"A": 1234}' | python3.8 hc1_sign.py | python3.8 hc1_verify.py```
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

1. Fetch the Base45 from https://dev.a-sit.at/certservice
1. Remove the first 2 bytes and do

   ```pbpaste| sed -e 's/^00//' | python3.8 hc1_verify.py --base64 --ignore-signature --cbor```
