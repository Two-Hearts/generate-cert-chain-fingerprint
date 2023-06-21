import cbor2
import argparse
import hashlib

COSE_X5CHAIN = 33

def cert_chain_sha256(file_path):
    with open(file_path, 'rb') as fp:
        cose_sign1 = cbor2.decoder.load(fp).value
        ###
        #    The COSE_Sign1 structure is a CBOR array. The fields of the array
        #    in order are:
        #    protected
        #    unprotected: the certificat chain is included here
        #    payload
        #    signature
        ###
        if len(cose_sign1) <= 1:
            raise Exception("COSE signature envelope missing unprotected header")
        unprotected = cose_sign1[1]
        if COSE_X5CHAIN not in unprotected:
            raise Exception("COSE signature envelope unprotected header does not contain x5chain")
        cert_chain = unprotected[COSE_X5CHAIN]
        results=[]
        for cert in cert_chain:
            h = hashlib.new('sha256')
            h.update(cert)
            results.append(h.hexdigest())
        print(str(results))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-f', '--file_path', metavar='file_path', type=str, 
        help='file path of a single COSE signature envelope', required=True, 
        nargs=1, dest="file_path")
    args = parser.parse_args()
    cert_chain_sha256(args.file_path[0])