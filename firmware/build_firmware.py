#!/usr/bin/env python3
import os
import subprocess
import shutil

def build_firmware():
    """펌웨어 바이너리 빌드"""
    print("Building infotainment firmware...")
    
    # 소스 파일 복사
    src_path = "../infotainment/info.c"
    makefile_path = "../infotainment/Makefile"
    
    if not os.path.exists(src_path):
        print("Error: Source file not found")
        return False
    
    # 임시 빌드 디렉토리
    build_dir = "build_temp"
    os.makedirs(build_dir, exist_ok=True)
    
    try:
        # 파일 복사
        shutil.copy(src_path, f"{build_dir}/info.c")
        shutil.copy(makefile_path, f"{build_dir}/Makefile")
        
        # 컴파일
        result = subprocess.run(
            ["make", "-C", build_dir],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            # 바이너리 복사
            shutil.copy(f"{build_dir}/infotainment_service", "infotainment_firmware.bin")
            print("Firmware built successfully: infotainment_firmware.bin")
            return True
        else:
            print(f"Build failed: {result.stderr}")
            return False
            
    finally:
        # 정리
        shutil.rmtree(build_dir, ignore_errors=True)

if __name__ == "__main__":
    build_firmware()
