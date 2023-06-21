# generate-cert-chain-thumbprint
This script takes in a valid COSE signature envelope and prints out to standard
output the SHA256 thumbprints of the certificate chain under x5chain of the
COSE envelope.<br>
The printout order is as follows: [leaf cert, intermediate cert, ..., root cert]

## Usage
`python generate-cert-chain-thumbprint.py -f ./cose_signature_envelope.sig` <br>
`python generate-cert-chain-thumbprint.py --file_path ./cose_signature_envelope.sig`
