#!/usr/bin/env python3
"""
ECU Firmware Builder Tool
Creates binwalk-analyzable firmware files from user binaries
"""

import os
import sys
import json
import struct
import argparse
import hashlib
import time
from pathlib import Path
import tempfile
import subprocess

class FirmwareBuilder:
    def __init__(self):
        self.MAGIC = b"VECU"  # Custom magic bytes
        self.VERSION = 0x0001
        self.header_size = 64  # Fixed header size
        
    def create_header(self, initramfs_size, initramfs_offset, checksum):
        """Create custom firmware header"""
        header = bytearray(self.header_size)
        
        # Magic bytes (4 bytes)
        header[0:4] = self.MAGIC
        
        # Version (2 bytes)
        struct.pack_into('<H', header, 4, self.VERSION)
        
        # Timestamp (4 bytes)
        struct.pack_into('<I', header, 6, int(time.time()))
        
        # InitramFS offset (4 bytes)
        struct.pack_into('<I', header, 10, initramfs_offset)
        
        # InitramFS size (4 bytes)
        struct.pack_into('<I', header, 14, initramfs_size)
        
        # Checksum (32 bytes - SHA256)
        header[18:50] = checksum
        
        # Reserved bytes (14 bytes)
        # Can be used for additional metadata
        
        return bytes(header)
    
    def create_initramfs(self, binary_mappings, config):
        """Create initramfs cpio archive"""
        with tempfile.TemporaryDirectory() as temp_dir:
            rootfs_dir = Path(temp_dir) / "rootfs"
            rootfs_dir.mkdir()
            
            # Create basic directory structure
            for dir_path in config.get('directories', ['/bin', '/sbin', '/etc', '/tmp', '/dev']):
                (rootfs_dir / dir_path.lstrip('/')).mkdir(parents=True, exist_ok=True)
            
            # Copy binaries to their destinations
            for src_path, dest_path in binary_mappings.items():
                src = Path(src_path)
                if not src.exists():
                    raise FileNotFoundError(f"Binary not found: {src_path}")
                
                dest = rootfs_dir / dest_path.lstrip('/')
                dest.parent.mkdir(parents=True, exist_ok=True)
                
                # Copy binary and set permissions
                with open(src, 'rb') as f_src, open(dest, 'wb') as f_dest:
                    f_dest.write(f_src.read())
                
                # Set executable permissions
                dest.chmod(0o755)
                print(f"Added binary: {src_path} -> {dest_path}")
            
            # Create additional files from config
            for file_info in config.get('files', []):
                file_path = rootfs_dir / file_info['path'].lstrip('/')
                file_path.parent.mkdir(parents=True, exist_ok=True)
                
                with open(file_path, 'w') as f:
                    f.write(file_info.get('content', ''))
                
                if 'permissions' in file_info:
                    file_path.chmod(int(file_info['permissions'], 8))
                
                print(f"Created file: {file_info['path']}")
            
            # Create cpio archive
            cpio_path = Path(temp_dir) / "initramfs.cpio"
            
            # Use find and cpio to create the archive
            cmd = f"cd {rootfs_dir} && find . | cpio -o -H newc > {cpio_path}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode != 0:
                raise RuntimeError(f"Failed to create cpio archive: {result.stderr}")
            
            # Read the cpio archive
            with open(cpio_path, 'rb') as f:
                return f.read()
    
    def calculate_checksum(self, data):
        """Calculate SHA256 checksum"""
        return hashlib.sha256(data).digest()
    
    def build_firmware(self, binary_mappings, config, output_path):
        """Build the complete firmware file"""
        print("Building ECU firmware...")
        print(f"Target architecture: aarch64")
        print(f"Binaries to include: {len(binary_mappings)}")
        
        # Create initramfs
        print("Creating initramfs...")
        initramfs_data = self.create_initramfs(binary_mappings, config)
        initramfs_size = len(initramfs_data)
        initramfs_offset = self.header_size
        
        print(f"InitramFS size: {initramfs_size} bytes")
        
        # Calculate checksum of initramfs
        checksum = self.calculate_checksum(initramfs_data)
        
        # Create header
        header = self.create_header(initramfs_size, initramfs_offset, checksum)
        
        # Write firmware file
        with open(output_path, 'wb') as f:
            f.write(header)
            f.write(initramfs_data)
        
        print(f"Firmware created: {output_path}")
        print(f"Total size: {len(header) + len(initramfs_data)} bytes")
        print(f"Header size: {len(header)} bytes")
        print(f"InitramFS size: {len(initramfs_data)} bytes")
        
        # Print binwalk analysis hint
        print("\n--- Binwalk Analysis Hint ---")
        print(f"Magic signature: {self.MAGIC.decode()}")
        print(f"InitramFS offset: 0x{initramfs_offset:08X}")
        print("Try: binwalk -e your_firmware.bin")

def load_config(config_path):
    """Load configuration file"""
    if not config_path or not Path(config_path).exists():
        # Return default config
        return {
            'directories': ['/bin', '/sbin', '/etc', '/tmp', '/dev'],
            'files': [
                {
                    'path': '/etc/version',
                    'content': 'ECU Firmware v1.0\nBuild: Development\n',
                    'permissions': '644'
                }
            ]
        }
    
    with open(config_path, 'r') as f:
        return json.load(f)

def main():
    parser = argparse.ArgumentParser(description='ECU Firmware Builder')
    parser.add_argument('--binary', action='append', required=True,
                       help='Binary mapping: src_path:dest_path')
    parser.add_argument('--config', help='Configuration JSON file')
    parser.add_argument('--output', required=True, help='Output firmware file')
    
    args = parser.parse_args()
    
    # Parse binary mappings
    binary_mappings = {}
    for mapping in args.binary:
        if ':' not in mapping:
            print(f"Error: Invalid binary mapping format: {mapping}")
            print("Expected format: src_path:dest_path")
            sys.exit(1)
        
        src, dest = mapping.split(':', 1)
        binary_mappings[src] = dest
    
    # Load configuration
    config = load_config(args.config)
    
    # Build firmware
    builder = FirmwareBuilder()
    try:
        builder.build_firmware(binary_mappings, config, args.output)
        print("\n✓ Firmware build completed successfully!")
    except Exception as e:
        print(f"✗ Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()