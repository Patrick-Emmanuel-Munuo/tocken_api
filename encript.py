from flask import Flask, jsonify, request
from flask_cors import CORS
from datetime import datetime, timedelta
import math
import binascii
from Crypto.Cipher import DES
import base64
import random

# Initialize Flask app and CORS
app = Flask(__name__)
CORS(app)

# Constants and globals
token_class = 0
token_sub_class = 0
base_date = datetime(2012, 1, 1, 0, 0, 0)

key_type = "01"
supply_group_code = "1234"
tariff_index = "01"
key_revision_number = "00"
decoder_reference_number = "1234567890"  # Decoder reference number (DRN)


def dec_to_bin(decimal, length):
    """Convert decimal number to binary string padded to length."""
    return bin(decimal)[2:].zfill(length)

def bin_to_hex(binary_str):
    """Convert binary string to uppercase hex string without 0x."""
    return hex(int(binary_str, 2))[2:].upper()

def hex_to_byte_array(hex_str):
    """Convert hex string to byte array."""
    return bytes.fromhex(hex_str)

def bin_str_to_bytes(bin_str):
    """Convert binary string to bytes, padded to full bytes."""
    padded = bin_str.zfill(((len(bin_str) + 7) // 8) * 8)
    return int(padded, 2).to_bytes(len(padded) // 8, byteorder='big')

def bytes_to_bin_str(b):
    """Convert bytes to binary string."""
    return ''.join(f'{byte:08b}' for byte in b)

#(key_type, supply_group_code, tariff_index, key_revision_number, decoder_reference_number)
def generate_decoder_key():
    try:
        """Generate binary string for decoder key based on inputs."""
        def convert(number_str, bit_length):
            number_int = int(number_str)
            return format(number_int, f'0{bit_length}b')
        key_type_bin = convert(key_type, 4)
        supply_group_bin = convert(supply_group_code, 16)
        tariff_index_bin = convert(tariff_index, 4)
        key_revision_bin = convert(key_revision_number, 8)
        drn_bin = convert(decoder_reference_number, 32)

        data_block_bin = key_type_bin + supply_group_bin + tariff_index_bin + key_revision_bin + drn_bin

        if len(data_block_bin) != 64:
            raise ValueError(f"Generated decoder key is not 64 bits: got {len(data_block_bin)} bits")

        return {
            "success": True,
            "message": data_block_bin
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Decoder key generation failed: {str(e)}"
        }

def get_mantissa(units):
    try:
        """Calculate exponent and mantissa from amount."""
        # Convert to integer amount (multiply by 10)
        amount = int(round(units * 10))  # Convert to integer
        # Get exponent
        if amount <= 16383:
            exponent = 0
        elif amount <= 180214:
            exponent = 1
        elif amount <= 1818524:
            exponent = 2
        else:
            exponent = 3
        # Calculate mantissa
        if exponent == 0:
            mantissa = amount
        else:
            rhs_sum = sum(int(2**14 * 10**(i - 1)) for i in range(1, exponent + 1))
            mantissa = round((amount - rhs_sum) / (10**exponent))
        mantissa = int(mantissa + 0.5)
        return {
            "success": True,
            "message": {
                "exponent": exponent,
                "mantissa": mantissa
            }
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Mantissa calculation failed: {str(e)}"
        }

def calculate_crc16(data: bytes, poly=0x1021, init_crc=0xFFFF) -> dict:
    try:
        crc = init_crc
        for byte in data:
            crc ^= byte << 8
            for _ in range(8):
                if (crc & 0x8000):
                    crc = (crc << 1) ^ poly
                else:
                    crc <<= 1
                crc &= 0xFFFF
        return {
            "success": True,
            "message": format(crc, '016b')
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"CRC16 calculation failed: {str(e)}"
        }

def build_string(*args):
    """Concatenate strings."""
    return ''.join(args)

def build_64_bit_token_block(units):
    """Build 64-bit token block."""
    def get_class_block():
        return dec_to_bin(token_class, 2)

    def get_subclass_block():
        return dec_to_bin(token_sub_class, 4)

    def get_rnd_block():
        rnd = random.randint(0, 15)  # 4-bit random number (0 to 15)
        return dec_to_bin(rnd, 4)

    def get_tid_block():
        issue_date_time = datetime.now()
        formatted_time = issue_date_time.strftime("%Y-%m-%d %H:%M:%S")
        minutes = int((issue_date_time - base_date).total_seconds() // 60)
        return dec_to_bin(minutes, 24)

    def get_amount_block(exponent, mantissa):
        return dec_to_bin(exponent, 2) + dec_to_bin(mantissa, 14)

    cls = get_class_block()
    subclass = get_subclass_block()
    rnd_block = get_rnd_block()
    tid_block = get_tid_block()
    mantissa_result = get_mantissa(units)
    if not mantissa_result["success"]:
        raise Exception(mantissa_result["message"])
    exponent = mantissa_result["message"]["exponent"]
    mantissa = mantissa_result["message"]["mantissa"]
    amount_block = get_amount_block(exponent, mantissa)
    initial_50_bit_block = build_string(subclass, rnd_block, tid_block, amount_block)

    # Calculate CRC for the 50-bit block
    hex_str = bin_to_hex(initial_50_bit_block)
    hex_str = hex_str.zfill(14)  # Pad to 56 bits (14 hex characters)
    byte_array = hex_to_byte_array(hex_str)
    crc_result = calculate_crc16(byte_array)
    if not crc_result["success"]:
        raise Exception(crc_result["message"])
    crc_block = crc_result["message"]
    token_64_bit_block = build_string(initial_50_bit_block, crc_block)
    return {
        "exponent": exponent,
        "mantissa": mantissa,
        "units": units,
        "cls": cls,
        "subclass": subclass,
        "rnd_block": rnd_block,
        "tid_block": tid_block,
        "crc_block": crc_block,
        "token_64_bit_block": token_64_bit_block,
    }

def encrypt(data: bytes, key: bytes):
    try:
        """Encrypt 8-byte data with 8-byte key using DES ECB."""
        if len(data) != 8 or len(key) != 8:
            return {
                "success": False,
                "message": "Both data and key must be exactly 8 bytes."
            }
        
        cipher = DES.new(key, DES.MODE_ECB)
        encrypted = cipher.encrypt(data)
        
        return {
            "success": True,
            "message": encrypted  # Optionally encode to hex or base64
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Encryption failed: {str(e)}"
        }

def convert_to_token_number(token_block_bin: str) -> str:
    """Convert 66-bit token binary to 20-digit utility token string."""
    token_number = int(token_block_bin, 2)
    token_number_str = str(token_number).zfill(20)
    token_parts = [token_number_str[i:i + 4] for i in range(0, len(token_number_str), 4)]
    return '-'.join(token_parts)

def process_token(token_block_bin: str, decoding_key_bin: str):
    try:
        key_bytes = bin_str_to_bytes(decoding_key_bin)
        data_bytes = bin_str_to_bytes(token_block_bin)
        enc_result = encrypt(data_bytes, key_bytes)
        if not enc_result["success"]:
            return {"success": False, "message": enc_result["message"]}
        encrypted_bin_str = bytes_to_bin_str(enc_result["message"])
        token = convert_to_token_number(encrypted_bin_str)
        return {
            "success": True,
            "message": token
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Token processing failed: {str(e)}"
        }

@app.route("/generate_token", methods=["GET"])
def api_encrypt():
    try:
        units_str = request.args.get("units", "0")
        units_float = float(units_str)
        units = int(units_float * 10) / 10
        decoder_key_result = generate_decoder_key()
        if not decoder_key_result["success"]:
            return jsonify({"success": False, "message": decoder_key_result["message"]}), 500
        decoder_key_bin = decoder_key_result["message"]
        token_data = build_64_bit_token_block(units)
        token_64_bit_block = token_data["token_64_bit_block"]
        utility_token = process_token(token_64_bit_block, decoder_key_bin)
        return jsonify({
            "success": True,
            "message": {
                "token_data": token_data,
                "utility_token": utility_token
            }
        })
    except ValueError as ve:
        return jsonify({
            "success": False,
            "message": f"Validation error: {str(ve)}"
        }), 400
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"An error occurred: {str(e)}"
        }), 500

if __name__ == "__main__":
    app.run(debug=True, port = 1000)
