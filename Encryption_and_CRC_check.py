import subprocess
import struct
import logging
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Paths and settings
CUBE_IDE_PATH = Path(r"C:\ST\STM32CubeIDE_1.14.1\STM32CubeIDE\stm32cubeide.exe")
WORKSPACE_PATH = Path(r"C:\Users\Teddy Roosevelt\STM32CubeIDE\workspace_1.14.1")
PROJECT_NAME = "RSI_project"
PROJECT_SRC_PATH = Path(r"C:\Users\Teddy Roosevelt\Desktop\Project_RSI_Gr2") / PROJECT_NAME  # Separate project source path
PRIVATE_KEY_PATH = Path(r"C:\Users\Teddy Roosevelt\SW_certs\private_key.pem")
OUTPUT_BIN = PROJECT_SRC_PATH / "Debug" / f"{PROJECT_NAME}.bin"
SIGNED_BIN = PROJECT_SRC_PATH / "Debug" / f"{PROJECT_NAME}_signed.bin"
CRC_FILE = PROJECT_SRC_PATH / "Debug" / f"{PROJECT_NAME}_crc.txt"

def check_file_exists(file_path):
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

def run_subprocess(cmd):
    logging.info(f"Running command: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        logging.debug(f"Command output: {result.stdout}")
        logging.info("Command completed successfully")
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed with return code {e.returncode}")
        logging.error(f"Error output: {e.stderr}")
        raise

def build_firmware():
    cmd = [
        str(CUBE_IDE_PATH),
        "--launcher.suppressErrors",
        "-noSplash",
        "-application", "org.eclipse.cdt.managedbuilder.core.headlessbuild",
        "-data", str(WORKSPACE_PATH),
        "-import", str(PROJECT_SRC_PATH),
        "-build", PROJECT_NAME
    ]
    run_subprocess(cmd)

def sign_firmware():
    logging.info("Signing firmware")
    check_file_exists(PRIVATE_KEY_PATH)
    check_file_exists(OUTPUT_BIN)

    with PRIVATE_KEY_PATH.open("rb") as key_file:
        private_key = RSA.import_key(key_file.read())

    with OUTPUT_BIN.open("rb") as f:
        firmware = f.read()

    h = SHA256.new(firmware)
    signature = pkcs1_15.new(private_key).sign(h)

    with SIGNED_BIN.open("wb") as f:
        f.write(struct.pack("<I", len(firmware)))  # Firmware size
        f.write(signature)  # 256-byte signature
        f.write(firmware)
    logging.info("Firmware signed successfully")

def calculate_crc(data):
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0xEDB88320 * (crc & 1))
    return crc ^ 0xFFFFFFFF

def add_crc():
    logging.info("Adding CRC to signed firmware")
    check_file_exists(SIGNED_BIN)

    with SIGNED_BIN.open("rb") as f:
        data = f.read()

    crc = calculate_crc(data)

    with SIGNED_BIN.open("ab") as f:
        f.write(struct.pack("<I", crc))

    with CRC_FILE.open("w") as f:
        f.write(f"{crc:08X}\n")

    logging.info(f"CRC {crc:08X} added to signed firmware and written to {CRC_FILE}")

def main():
    try:
        build_firmware()
        sign_firmware()
        add_crc()
        logging.info("Firmware built, signed, and CRC added successfully!")
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main()
