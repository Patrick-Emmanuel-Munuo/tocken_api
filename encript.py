from flask import Flask, jsonify, request
from flask_cors import CORS
from datetime import datetime, timedelta
import math
import binascii
import base64
import random
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad


# Initialize Flask app and CORS
app = Flask(__name__)
CORS(app)

# Constants and globals
token_class = 0
token_sub_class = 0
base_date = datetime(2022, 1, 1, 0, 0, 0).strftime("%Y-%m-%d %H:%M:%S")
#025-06-07 15:28:00
"""
For 16 bytes (128 bits) key:

key_type	8	supports up to 255
supply_group_code	16	supports up to 65535
tariff_index	8	supports up to 255
key_revision_number	8	supports up to 255
decoder_reference_number (DRN)	64	use 64 bits (max ~1.8e19)
Total	128	Perfect for 16 bytes
"""

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

def generate_decoder_key():
    try:
        # Input values (example)
        key_type = 21
        supply_group_code = 12345
        tariff_index = 3
        key_revision_number = 0
        decoder_reference_number = 1234567890
        secret_key = "12345"  # 16 hex chars = 64 bits
        def convert(number_str, bit_length):
            number_int = int(number_str)
            return format(number_int, f'0{bit_length}b')
        key_type_bin = convert(key_type, 8)  # Key type is 8 bits
        supply_group_bin = convert(supply_group_code, 16) # Supply group code is 16 bits
        tariff_index_bin = convert(tariff_index, 8) # Tariff index is 8 bits
        key_revision_bin = convert(key_revision_number, 8) # Key revision number is 8 bits
        # Decoder reference number (DRN) is 64 bits
        drn_bin = convert(decoder_reference_number, 64) # 64 bits (max ~1.8e19)v
        secret_key_bin = convert(secret_key, 24)       # 24 bits
        # Combine all parts into a 128-bit binary string

        data_block_bin = key_type_bin + supply_group_bin + tariff_index_bin + key_revision_bin + drn_bin + secret_key_bin

        if len(data_block_bin) != 128:
            raise ValueError(f"Generated decoder key is not 64 bits: got {len(data_block_bin)} bits")
        key_128_bin = data_block_bin # + data_block_bin
        return {
            "success": True,
            "message": key_128_bin
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Decoder key generation failed: {str(e)}"
        }

def get_mantissa(units):
    try:
        """
        Custom 16-bit representation:
        - 4-bit exponent (0–15) = power of 10
        - 12-bit mantissa (0–4095)
        - 2-decimal precision using units * 100
        """
        # Maintain 2-decimal accuracy
        # Try exponents from 0 to 15 to find smallest valid exponent
        # Convert to integer amount (multiply by 100)
        amount = int(round(units * 100))
        if amount <= 16383:
            exponent = 0
        elif amount <= 180214:
            exponent = 1
        elif amount <= 1818524:
            exponent = 2
        else:
            exponent = 3
        # Calculate mantissa store 12bit 0 - 4095
        if exponent == 0:
            mantissa = amount
        else:
            rhs_sum = sum(int(math.pow(2,14) * math.pow(10, (i - 1))) for i in range(1, exponent + 1))
            mantissa =  int((amount - rhs_sum) / (math.pow(10, exponent)))  # Round to nearest integer
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

def encrypt(data: bytes, key: bytes):
    """
    Encrypt exactly 8 bytes of data using 3DES (ECB mode, no padding).
    :param data: exactly 8 bytes
    :param key: 16 or 24 bytes key
    :return: dict with success bool and message (encrypted bytes or error)
    """
    if len(data) != 8:
        return {
            "success": False,
            "message": f"Data is {len(data)} must be exactly 8 bytes."
        }
    if len(key) not in (16, 24):
        return {
            "success": False,
            "message": f"Key length is {len(key)} bytes. Key must be either 16 or 24 bytes for 3DES."
        }
    try:
        key = DES3.adjust_key_parity(key)
        cipher = DES3.new(key, DES3.MODE_ECB)
        encrypted = cipher.encrypt(data)  # no padding because data must be 8 bytes exactly
        return {
            "success": True,
            "message": encrypted
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Encryption failed: {str(e)}"
        }

def build_64_bit_token_block(units):
    """Build 64-bit token block."""
    try:
        
        issue_date =  datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        def get_class_block():
            return dec_to_bin(token_class, 2)

        def get_subclass_block():
            return dec_to_bin(token_sub_class, 4)
        
        def get_rnd_block():
            rnd = random.randint(0, 15)  # 4-bit random number (0 to 15)
            return dec_to_bin(rnd, 4)
        
        def get_tid_block():
            issued_date = datetime.strptime(issue_date, "%Y-%m-%d %H:%M:%S")
            base_date_time = datetime.strptime(base_date, "%Y-%m-%d %H:%M:%S")
            minutes = int((issued_date - base_date_time).total_seconds() // 60)
            return dec_to_bin(minutes, 24)
        
        def get_amount_block(exponent, mantissa):
            return dec_to_bin(exponent, 2) + dec_to_bin(mantissa, 14)
        
        cls = get_class_block()
        subclass = get_subclass_block()
        rnd_block = get_rnd_block()
        tid_block = get_tid_block()
        mantissa_result = get_mantissa(units)
        if not mantissa_result["success"]:
            return {"success": False, "message": mantissa_result["message"]}
        exponent = mantissa_result["message"]["exponent"]
        mantissa = mantissa_result["message"]["mantissa"]
        amount_block = get_amount_block(exponent, mantissa)
        initial_50_bit_block = build_string(cls, subclass, rnd_block, tid_block, amount_block)
        # CRC Calculation
        hex_str = bin_to_hex(initial_50_bit_block)
        hex_str = hex_str.zfill(14)  # Pad to 56 bits (14 hex characters)
        byte_array = hex_to_byte_array(hex_str)
        crc_result = calculate_crc16(byte_array)
        if not crc_result["success"]:
            return {"success": False, "message": crc_result["message"]}
        crc_block = crc_result["message"]
        token_64_bit_block = build_string(subclass, rnd_block, tid_block, amount_block, crc_block)
        return {
            "success": True,
            "message": {
                "exponent": exponent,
                "mantissa": mantissa,
                "amount_block": amount_block,
                "units": float(units),
                "cls": cls,
                "base_date":base_date,
                #"subclass": subclass_val,
                #"random": rnd_val,
                #"token_identifier_minutes": tid_minutes,
                "token_issue_datetime": issue_date,
                "subclass": subclass,
                "rnd_block": rnd_block,
                "tid_block": tid_block,
                "crc_block": crc_block,
                "token_64_bit_block": token_64_bit_block
            }
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Error in build_64_bit_token_block: {str(e)}"
        }

def insert_and_transposition_class_bits(encrypted_token_block: str, token_class: str) -> str:
    # Prepend token_class bits to the encrypted token block
    with_class_bits = token_class + encrypted_token_block
    # Convert strings to lists for easy manipulation
    token_class_bits = list(token_class)
    token_block_bits = list(with_class_bits)
    length = len(with_class_bits)
    # Perform the bit swaps (transposition)
    token_block_bits[length - 1 - 65] = token_block_bits[length - 1 - 28]
    token_block_bits[length - 1 - 64] = token_block_bits[length - 1 - 27]
    token_block_bits[length - 1 - 28] = token_class_bits[0]
    token_block_bits[length - 1 - 27] = token_class_bits[1]
    # Join bits back into a string and return
    return "".join(token_block_bits)

def process_token(token_block_bin: str, decoding_key_bin: str):
    try:
        key_bytes = bin_str_to_bytes(decoding_key_bin)
        data_bytes = bin_str_to_bytes(token_block_bin)
        enc_result = encrypt(data_bytes, key_bytes)
        if not enc_result["success"]:
            return {"success": False, "message": enc_result["message"]}
        encrypted_bin_str = bytes_to_bin_str(enc_result["message"])
        cls = dec_to_bin(token_class, 2)
        final_66_bit_token = insert_and_transposition_class_bits(encrypted_bin_str, cls)
        token_number = int(final_66_bit_token, 2)
        token_number_str = str(token_number).zfill(20)
        token_parts = [token_number_str[i:i + 4] for i in range(0, len(token_number_str), 4)]
        token = '-'.join(token_parts)
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
        units = int(units_float * 100) / 100
        decoder_key_result = generate_decoder_key()
        if not decoder_key_result["success"]:
            return jsonify({"success": False, "message": decoder_key_result["message"]}), 500
        decoder_key_bin = decoder_key_result["message"]
        token_data = build_64_bit_token_block(units)
        if not token_data["success"]:
            return jsonify({ 
                "success" : False, 
                "message": token_data["message"] 
                }), 500
        token_64_bit_block = token_data["message"]["token_64_bit_block"]
        utility_token = process_token(token_64_bit_block, decoder_key_bin)
        
        if not utility_token["success"]:
            return jsonify({
                "success": False,
                "message": utility_token["message"]
                })
        return jsonify({
            "success": True,
            "message": {
                "utility_token": utility_token["message"],
                **token_data["message"]
            }
            }), 200
    except ValueError as ve:
        return jsonify({
            "success": False,
            "message": f"api_encrypt Validation error: {str(ve)}"
        }), 400
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"api_encrypt An error occurred: {str(e)}"
        }), 500
if __name__ == "__main__":
    app.run(debug=True, port = 1000)
