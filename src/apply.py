import argparse
import zipfile
import io
import base64
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

import common

def main():
    # Parse arguments
    argp = argparse.ArgumentParser()
    argp.add_argument('-k', '--pubkey', type=str, required=True, help='RSA public key path')
    argp.add_argument('patch_path', type=str, help='Patch file path')
    argp.add_argument('-d', '--dest', type=str, required=True, help='Target directory')
    args = argp.parse_args()

    # Load RSA public key
    with open(args.pubkey, mode='br') as f:
        public_key = RSA.import_key(f.read())

    with zipfile.ZipFile(args.patch_path) as patch_zip:
        if 'patch_entity.zip' not in patch_zip.namelist():
            raise RuntimeError('Patch entity not found.')
        if 'signature.txt' not in patch_zip.namelist():
            raise RuntimeError('Signature not found.')

        patch_zip_hash = common.io_hash(patch_zip.open('patch_entity.zip', mode='r'))
        sig_file_text = patch_zip.read('signature.txt')
        signature = base64.b64decode(sig_file_text)

        # print('File hash value:', patch_zip_hash)
        # print('Saved signature:', sig_file_text)

        try:
            pkcs1_15.new(public_key).verify(patch_zip_hash, signature)
        except ValueError:
            print('Verification failed.')
            return
        
        with zipfile.ZipFile(io.BytesIO(patch_zip.read('patch_entity.zip'))) as patch_entity_zip:
            patch_entity_zip.extractall(args.dest)
        
        print('Done.')


if __name__ == "__main__":
    main()
