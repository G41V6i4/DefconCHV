#!/usr/bin/env python3
"""
Manual firmware extractor (without binwalk dependency)
"""

import struct
import sys
import os
import subprocess
import tempfile
from pathlib import Path

def extract_firmware(firmware_path, output_dir=None):
    """Extract firmware manually"""
    
    if not os.path.exists(firmware_path):
        print(f"Error: Firmware file not found: {firmware_path}")
        return False
    
    if output_dir is None:
        firmware_name = Path(firmware_path).stem
        output_dir = f"{firmware_name}_extracted"
    
    print(f"Extracting firmware: {firmware_path}")
    print(f"Output directory: {output_dir}")
    
    with open(firmware_path, 'rb') as f:
        # Read header
        header = f.read(64)
        
        if len(header) < 64:
            print("Error: Invalid firmware file (too small)")
            return False
        
        # Parse header
        magic = header[0:4]
        version = struct.unpack('<H', header[4:6])[0]
        timestamp = struct.unpack('<I', header[6:10])[0]
        initramfs_offset = struct.unpack('<I', header[10:14])[0]
        initramfs_size = struct.unpack('<I', header[14:18])[0]
        checksum = header[18:50]
        
        print(f"Magic: {magic}")
        print(f"Version: 0x{version:04X}")
        print(f"Timestamp: {timestamp}")
        print(f"InitramFS offset: 0x{initramfs_offset:08X}")
        print(f"InitramFS size: {initramfs_size} bytes")
        print(f"Checksum: {checksum.hex()[:16]}...")
        
        if magic != b"VECU":
            print("Warning: Magic bytes don't match expected 'VECU'")
        
        # Seek to initramfs
        f.seek(initramfs_offset)
        initramfs_data = f.read(initramfs_size)
        
        if len(initramfs_data) != initramfs_size:
            print(f"Error: Could not read full initramfs data")
            return False
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Save initramfs
        cpio_path = os.path.join(output_dir, "initramfs.cpio")
        with open(cpio_path, 'wb') as cpio_file:
            cpio_file.write(initramfs_data)
        
        print(f"Saved initramfs: {cpio_path}")
        
        # Extract cpio archive
        rootfs_dir = os.path.join(output_dir, "rootfs")
        os.makedirs(rootfs_dir, exist_ok=True)
        
        try:
            # Use cpio to extract
            cmd = f"cd {rootfs_dir} && cpio -i < {os.path.abspath(cpio_path)}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"Successfully extracted rootfs to: {rootfs_dir}")
                
                # List extracted files
                print("\nExtracted files:")
                for root, dirs, files in os.walk(rootfs_dir):
                    for file in files:
                        rel_path = os.path.relpath(os.path.join(root, file), rootfs_dir)
                        file_path = os.path.join(root, file)
                        file_size = os.path.getsize(file_path)
                        print(f"  {rel_path} ({file_size} bytes)")
                
                return True
            else:
                print(f"Error extracting cpio: {result.stderr}")
                print("Trying alternative extraction method...")
                
                # Try with different cpio options
                cmd = f"cd {rootfs_dir} && cpio -idmv < {os.path.abspath(cpio_path)}"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if result.returncode == 0:
                    print(f"Successfully extracted with alternative method")
                    return True
                else:
                    print(f"Alternative extraction also failed: {result.stderr}")
                    return False
                    
        except Exception as e:
            print(f"Error during extraction: {e}")
            return False

def analyze_firmware(firmware_path):
    """Analyze firmware structure (like binwalk)"""
    
    print(f"=== Firmware Analysis: {firmware_path} ===")
    
    with open(firmware_path, 'rb') as f:
        file_size = os.path.getsize(firmware_path)
        print(f"File size: {file_size} bytes")
        
        # Read and analyze header
        header = f.read(64)
        magic = header[0:4]
        initramfs_offset = struct.unpack('<I', header[10:14])[0]
        initramfs_size = struct.unpack('<I', header[14:18])[0]
        
        print("\nDECIMAL\t\tHEXADECIMAL\tDESCRIPTION")
        print("-------\t\t-----------\t-----------")
        print(f"0\t\t0x0\t\tCustom firmware header (magic: {magic})")
        print(f"{initramfs_offset}\t\t0x{initramfs_offset:X}\t\tASCII cpio archive (SVR4 with no CRC)")
        
        # Check for additional signatures
        f.seek(initramfs_offset)
        cpio_header = f.read(6)
        if cpio_header == b'070701':
            print(f"\t\t\t\t└─ New ASCII format")
        elif cpio_header == b'070702':
            print(f"\t\t\t\t└─ New ASCII format with CRC")
        
        end_offset = initramfs_offset + initramfs_size
        if end_offset < file_size:
            print(f"{end_offset}\t\t0x{end_offset:X}\t\tEnd of initramfs")

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print(f"  {sys.argv[0]} <firmware_file> [output_dir]")
        print(f"  {sys.argv[0]} --analyze <firmware_file>")
        sys.exit(1)
    
    if sys.argv[1] == '--analyze':
        if len(sys.argv) < 3:
            print("Error: Please specify firmware file to analyze")
            sys.exit(1)
        analyze_firmware(sys.argv[2])
    else:
        firmware_path = sys.argv[1]
        output_dir = sys.argv[2] if len(sys.argv) > 2 else None
        
        if extract_firmware(firmware_path, output_dir):
            print("\n✓ Extraction completed successfully!")
        else:
            print("\n✗ Extraction failed!")
            sys.exit(1)

if __name__ == '__main__':
    main()
