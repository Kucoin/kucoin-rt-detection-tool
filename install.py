#!/usr/bin/env python3
"""
KuCoin RT Detection Tool Installation Script
"""
import os
import sys
import subprocess
import time

def print_header(text):
    """Print formatted header"""
    print("\n" + "=" * 60)
    print(f"  {text}")
    print("=" * 60)

def check_python_version():
    """Check Python version"""
    if sys.version_info < (3, 7):
        print("ERROR: Python 3.7 or higher is required")
        print(f"Current version: {sys.version_info.major}.{sys.version_info.minor}")
        return False
    print(f"✓ Python {sys.version_info.major}.{sys.version_info.minor} detected")
    return True

def install_dependencies():
    """Install Python dependencies"""
    requirements_file = "requirements.txt"
    if not os.path.exists(requirements_file):
        print("ERROR: requirements.txt not found!")
        return False
    print("Installing packages from requirements.txt...")
    retries = 3
    for attempt in range(retries):
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "-r", requirements_file],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                print("✓ All dependencies installed successfully")
                return True
            else:
                print(f"Attempt {attempt + 1}/{retries} failed:")
                print(f"Error: {result.stderr}")
                if attempt < retries - 1:
                    print("Retrying in 3 seconds...")
                    time.sleep(3)
        except Exception as e:
            print(f"Error during installation: {e}")
            if attempt < retries - 1:
                print("Retrying in 3 seconds...")
                time.sleep(3)
    print("Failed to install dependencies after multiple attempts.")
    return False

def main():
    print_header("KuCoin RT Detection Tool Installer")
    if not check_python_version():
        sys.exit(1)
    if not install_dependencies():
        sys.exit(1)
    print("\nSetup complete. You can now run kucoin_rt_detection_tool.py.")

if __name__ == "__main__":
    main()
