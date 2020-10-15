import io
import os
import glob
from typing import Dict, Union
from Crypto.Hash import SHA256

FILE_HASH_UNIT = 2048
Hash = SHA256.SHA256Hash

def file_hash(path:str) -> Hash:
    with open(path, 'rb') as f:
        return io_hash(f)

def io_hash(bi:io.BytesIO) -> Hash:
    hash_value = SHA256.new()
    unit_length = SHA256.block_size * FILE_HASH_UNIT
    while True:
        content = bi.read(unit_length)
        if not content:
            break
        hash_value.update(content)
    return hash_value

def files_hash(path:str) -> Union[Hash, Dict[str, Union[Hash, dict]]]:
    if not os.path.isdir(path):
        return file_hash(path)
    return {cpath:files_hash(os.path.join(path, cpath)) for cpath in glob.glob(path)}
