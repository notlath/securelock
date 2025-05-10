#!/usr/bin/env python3
"""
File Hash Tampering Tool for SecureLock
---------------------------------------
This script specifically focuses on tampering with the file_hash field in SecureLock files
to demonstrate the integrity check functionality. When a tampered file is loaded into
SecureLock, it should detect that the computed hash doesn't match the stored hash
and display an error message, preventing the corrupted file from being processed.

The tampering process:
1. Opens a SecureLock encrypted file
2. Extracts and parses the metadata
3. Replaces the file_hash with an invalid value
4. Writes the modified file back to disk

To use:
1. Create a SecureLock encrypted file using securelock.py
2. Run this script on the encrypted file
3. Try to decrypt the tampered file using SecureLock
4. Observe that SecureLock detects the tampering
"""

import os
import json
import base64
import hashlib
import argparse
from typing import Tuple, Dict, Optional

def extract_securelock_components(file_path: str) -> Tuple[int, Dict, bytes]:
    """
    Extract components from a SecureLock file.
    
    Args:
        file_path: Path to the SecureLock file
        
    Returns:
        Tuple containing metadata size, parsed metadata dict, and encrypted data
    """
    with open(file_path, "rb") as f:
        # Read metadata size (first 4 bytes)
        metadata_size = int.from_bytes(f.read(4), byteorder='big')
        
        # Read and parse metadata
        metadata_json = f.read(metadata_size)
        metadata = json.loads(metadata_json.decode('utf-8'))
        
        # Read encrypted data
        encrypted_data = f.read()
        
    return metadata_size, metadata, encrypted_data

def tamper_file_hash(file_path: str, backup: bool = True) -> None:
    """
    Tamper with the file hash in a SecureLock file.
    
    Args:
        file_path: Path to the SecureLock file to tamper with
        backup: Whether to create a backup of the original file (default: True)
    """
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found")
        return
        
    if not file_path.endswith('.securelock'):
        print(f"Error: '{file_path}' does not appear to be a SecureLock file")
        return
    
    # Create backup if requested
    if backup:
        backup_path = f"{file_path}.backup"
        try:
            with open(file_path, "rb") as src, open(backup_path, "wb") as dst:
                dst.write(src.read())
            print(f"Created backup of original file as '{backup_path}'")
        except Exception as e:
            print(f"Warning: Could not create backup: {e}")
    
    try:
        # Extract components from SecureLock file
        _, metadata, encrypted_data = extract_securelock_components(file_path)
        
        # Display original file hash
        original_hash = metadata.get('file_hash', 'Not found')
        print(f"Original file hash: {original_hash}")
        
        # Generate a deliberately incorrect hash value
        # Option 1: Completely invalid random hash
        fake_hash = hashlib.sha256(os.urandom(32)).digest()
        metadata['file_hash'] = base64.b64encode(fake_hash).decode('utf-8')
        
        # Write the tampered file back to disk
        with open(file_path, "wb") as f:
            metadata_json = json.dumps(metadata).encode('utf-8')
            f.write(len(metadata_json).to_bytes(4, byteorder='big'))
            f.write(metadata_json)
            f.write(encrypted_data)
        
        print(f"Tampered file hash: {metadata['file_hash']}")
        print(f"File hash successfully tampered: {file_path}")
        print("\nNow try to decrypt this file using SecureLock.")
        print("You should see an integrity check error when decryption is attempted.")
        
    except Exception as e:
        print(f"Error tampering with file: {e}")

def main():
    """Main function to handle command line arguments."""
    parser = argparse.ArgumentParser(
        description='Tamper with file hash in SecureLock files to test integrity checks.'
    )
    parser.add_argument(
        'file', 
        help='Path to the SecureLock file to tamper with'
    )
    parser.add_argument(
        '--no-backup', 
        action='store_true',
        help='Do not create a backup of the original file'
    )
    
    args = parser.parse_args()
    
    # Tamper with the file hash
    tamper_file_hash(args.file, not args.no_backup)

if __name__ == "__main__":
    print("SecureLock File Hash Tampering Tool")
    print("----------------------------------")
    
    # Check if file path is provided as command line argument
    import sys
    if len(sys.argv) > 1:
        main()
    else:
        # Interactive mode
        file_path = "demo.txt.securelock"  # File path should be in quotes as it's a string
        create_backup = input("Create backup of original file? (y/n): ").lower() == 'y'
        tamper_file_hash(file_path, create_backup)
