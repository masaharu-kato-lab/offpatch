import argparse
import os
import shutil
import base64

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

import common

TEMP_DIR = 'tmp'

def main():
    # Parse arguments
    argp = argparse.ArgumentParser()
    argp.add_argument('-k', '--pubkey', type=str, required=True, help='RSA public key path')
    argp.add_argument('-prk', '--prvkey', type=str, required=True, help='RSA private key path')
    argp.add_argument('-pd', '--patch-dir', type=str, help='Patch files directory')
    argp.add_argument('-fd', '--full-dir', type=str, help='Full files directory (for calcuating hash values)')
    argp.add_argument('-o', '--output', type=str, required=True, help='Output path')
    args = argp.parse_args()

    # Load RSA public key
    with open(args.pubkey, mode='br') as f:
        public_key = RSA.import_key(f.read())

    # Load RSA private key
    with open(args.prvkey, mode='br') as f:
        private_key = RSA.import_key(f.read())

    # Prepare temporary directory to create patch
    temp_patch_dir = TEMP_DIR + '/c_patch'
    os.makedirs(temp_patch_dir, exist_ok=True)

    # Create a entity of patch
    shutil.make_archive(temp_patch_dir + '/patch_entity', 'zip', root_dir=args.patch_dir)
    
    # Calculate a signature from a hash value of the entity of patch
    file_hash_value = common.file_hash(temp_patch_dir + '/patch_entity.zip')
    signature_value = pkcs1_15.new(private_key).sign(file_hash_value)
    signature_text = base64.b64encode(signature_value).decode()

    # print('Files hash value:', file_hash_value.hexdigest())
    # print('Signature: ', signature_text)

    # Save signature text
    with open(temp_patch_dir + '/signature.txt', mode='w') as f:
        print(signature_text, end='', file=f)
    
    # Create final patch file
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    shutil.make_archive(os.path.splitext(args.output)[0], 'zip', root_dir=temp_patch_dir)

    # Remove temporary files and directory
    os.remove(temp_patch_dir + '/patch_entity.zip')
    os.remove(temp_patch_dir + '/signature.txt')
    os.rmdir(temp_patch_dir)


if __name__ == "__main__":
    main()
