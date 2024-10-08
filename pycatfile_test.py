import os
import unittest
from io import BytesIO

import pycatfile  # Ensure pycatfile.py is accessible


class TestPyCatFile(unittest.TestCase):
    def setUp(self):
        """Prepare environment for testing."""
        # Create example files to pack
        self.test_files = ['test_file1.txt', 'test_file2.txt']
        for file_name in self.test_files:
            with open(file_name, 'w') as f:
                f.write(f'Contents of {file_name}\n')

        # Name of the packed file for testing
        self.packed_file = 'test_packed.cat'

    def tearDown(self):
        """Clean up after tests."""
        # Remove created test files and packed file
        for file_name in self.test_files + [self.packed_file]:
            try:
                os.remove(file_name)
            except FileNotFoundError:
                pass  # File was not created or has been removed already

    def test_pack_files(self):
        """Test packing files into a single file."""
        # Assuming a function PackCatFile exists for packing files
        with open(self.packed_file, 'wb') as out_file:
            pycatfile.PackCatFile(
                self.test_files,
                out_file,
                compression="none",
                checksum="none",
                verbose=False)

        # Check if the packed file has been created
        self.assertTrue(os.path.exists(self.packed_file))

    def test_list_packed_files(self):
        """Test listing contents of a packed file."""
        # First, pack files into a single file
        with open(self.packed_file, 'wb') as out_file:
            pycatfile.PackCatFile(
                self.test_files,
                out_file,
                compression="none",
                checksum="none",
                verbose=False)

        # Assuming a function CatFileListFiles exists for listing contents
        with open(self.packed_file, 'rb') as in_file:
            contents = pycatfile.CatFileListFiles(in_file, verbose=False)

        # Check if the contents match the packed files
        expected_contents = set(self.test_files)
        self.assertEqual(set(contents), expected_contents)


if __name__ == '__main__':
    unittest.main()
