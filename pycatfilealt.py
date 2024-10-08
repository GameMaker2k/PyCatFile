import argparse
import logging
import os
import sys
import tarfile
import zlib
from io import BytesIO

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CatFilePacker:
    def __init__(self, checksum_type='crc32'):
        self.checksum_type = checksum_type

    def pack_from_tar(self, tar_path, catfile_path):
        try:
            with tarfile.open(tar_path, 'r') as tar, open(catfile_path, 'wb') as catfile:
                for member in tar.getmembers():
                    if member.isfile():
                        file_data = tar.extractfile(member).read()
                        packed_data = self._pack_file_data(file_data, member)
                        catfile.write(packed_data)
            return True
        except tarfile.TarError as e:
            logger.error(f"Tar file error: {e}")
            return False
        except IOError as e:
            logger.error(f"I/O error: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return False

    def _pack_file_data(self, data, member):
        metadata = self._create_metadata(member)
        checksum = self._calculate_checksum(data)
        metadata_length = len(metadata).to_bytes(4, byteorder='little')
        data_length = len(data).to_bytes(4, byteorder='little')
        packed_data = metadata_length + metadata + data_length + data + checksum
        return packed_data

    def _create_metadata(self, member):
        name = member.name.encode('utf-8')
        size = member.size.to_bytes(8, byteorder='little')
        mtime = member.mtime.to_bytes(8, byteorder='little')
        mode = member.mode.to_bytes(4, byteorder='little')
        metadata = name + size + mtime + mode
        return metadata

    def _calculate_checksum(self, data):
        if self.checksum_type == 'crc32':
            checksum = zlib.crc32(data).to_bytes(4, byteorder='little')
        else:
            checksum = b'\x00' * 4  # Placeholder for unsupported checksum types
        return checksum


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Pack files from a TAR archive into a CAT file.')
    parser.add_argument('tar_path', help='Path to the TAR file to pack')
    parser.add_argument('catfile_path', help='Path to the CAT file to create')
    args = parser.parse_args()

    packer = CatFilePacker(checksum_type='crc32')
    success = packer.pack_from_tar(args.tar_path, args.catfile_path)
    if success:
        logger.info("Packing completed successfully.")
    else:
        logger.error("Packing failed.")
