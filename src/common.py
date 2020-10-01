import io
from Crypto.Hash import SHA256

FILE_HASH_UNIT = 2048

def file_hash(path:str) -> SHA256.SHA256Hash:
    with open(path, 'rb') as f:
        return io_hash(f)

def io_hash(bi:io.BytesIO) -> SHA256.SHA256Hash:
    hash_value = SHA256.new()
    unit_length = SHA256.block_size * FILE_HASH_UNIT
    while True:
        content = bi.read(unit_length)
        if not content:
            break
        hash_value.update(content)
    return hash_value
