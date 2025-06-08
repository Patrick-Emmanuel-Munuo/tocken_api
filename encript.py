from flask import Flask, jsonify, request
from flask_cors import CORS
from datetime import datetime, timedelta
import math
import binascii
import base64
import random
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import struct

# Initialize Flask app and CORS
app = Flask(__name__)
CORS(app)

# Constants and globals
token_class = 0 # 0 for utility token
# Base date for TID calculation
base_date = datetime(2025, 5, 5, 0, 0, 0)


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

def encode_units(units):
    try:
        """
        Custom 20-bit representation:
        - 2-decimal precision using units * 100
        """
        # number bit 23 bits
        # number after decimal point to 2 decimal places ie .00 to .99 6bits
        # Maintain 2-decimal accuracy
        max_amount = 65530.0  # Maximum value units
        if units > max_amount:
            return {
                "success": False,
                "message": "units value too large to be represented."
        }
        number = int(units)
        decimal = int(round((units - number) * 100))
        number_bin = dec_to_bin(number,16) #16 bit
        decimal_bin = dec_to_bin(decimal,7) #7 bit
        return {
            "success": True,
            "message": {
                "number": number_bin,
                "decimal": decimal_bin,
                "amount_block": number_bin + decimal_bin  # 23 bits
            }
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Mantissa calculation failed: {str(e)}"
        }

def decode_units(packed_bin):
    try:
        if len(packed_bin) != 23:
            raise ValueError(f"Input binary string length must be 23 bits, got {len(packed_bin)}")
        
        number_bin = packed_bin[:16]  # first 16 bits for integer
        decimal_bin = packed_bin[16:]  # last 7 bits for decimal
        
        number = int(number_bin, 2)
        decimal = int(decimal_bin, 2)
        
        if decimal > 99:
            raise ValueError(f"Decimal part out of range (0-99), got {decimal}")
        
        units = number + decimal / 100.0
        
        return {
            "success": True,
            "message": round(units, 2)
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Decoding failed: {str(e)}"
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
        issue_date =  datetime.now()
        def get_class_block():
            return dec_to_bin(token_class, 2)
        
        def get_rnd_block(): #4 bits
            # Generate a random 1-bit number (0 to 1)
            rnd = random.randint(0, 1)  # 1-bit random number (0 to 1)
            return dec_to_bin(rnd, 1)
        
        def get_tid_block(): #24 bits
            #tid = random.randint(0, 16,777,215)  # 24-bit random number (0 to 16,777,215)
            minutes = int((issue_date - base_date).total_seconds() // 60)
            return dec_to_bin(minutes, 24)
        cls = get_class_block()
        rnd_block = get_rnd_block()
        tid_block = get_tid_block()
        units_result = encode_units(units)
        if not units_result["success"]:
           raise ValueError(units_result["message"]) 
        number = units_result["message"]["number"]
        decimal = units_result["message"]["decimal"]
        amount_block = units_result["message"]["amount_block"] #get_amount_block(number, decimal)#[:16]
        initial_50_bit_block = build_string(cls, rnd_block, tid_block, amount_block)
        # CRC Calculation
        hex_str = bin_to_hex(initial_50_bit_block)
        hex_str = hex_str.zfill(14)  # Pad to 56 bits (14 hex characters)
        byte_array = hex_to_byte_array(hex_str)
        crc_result = calculate_crc16(byte_array)
        #print(f"calculated CRC: {crc_result['message']}")
        if not crc_result["success"]:
            return {"success": False, "message": crc_result["message"]}
        crc_block = crc_result["message"]
        token_64_bit_block = build_string(rnd_block, tid_block, amount_block, crc_block)
        expired_datetime = issue_date + timedelta(days=365)
        return {
            "success": True,
            "message": { 
                "units_number": int(number, 2),
                "units_decimal": int(decimal, 2) ,
                #"unit_encoded": units,
                "amount_block": amount_block,
                "amount_block_length": len(amount_block),
                "units": float(units),
                "units_decoded": decode_units(amount_block)["message"],
                "cls": cls,
                "issue_datetime": issue_date.strftime("%Y-%m-%d %H:%M:%S"),
                "expired_datetime": expired_datetime.strftime("%Y-%m-%d %H:%M:%S"),
                "base_date": base_date.strftime("%Y-%m-%d %H:%M:%S"),
                "rnd_block": rnd_block,
                "tid_block": tid_block,
                "crc_block": crc_block,
                "crc_block": bin_to_hex(crc_block),
                "token_64_bit_block": token_64_bit_block
            }
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Error in build_64_bit_token_block: {str(e)}"
        }

def insert_and_transposition_class_bits(encrypted_token_block: str, token_class: str):
    try:
        # Prepend token_class bits to the encrypted token block
        with_class_bits = token_class + encrypted_token_block
        # Convert strings to lists for manipulation
        token_class_bits = list(token_class)
        token_block_bits = list(with_class_bits)
        length = len(with_class_bits)

        if length < 66:
            return {
                "success": False,
                "message": "Input token block must be at least 66 bits after prepending class bits"
            }
        # Perform the bit swaps (transposition)
        token_block_bits[length - 1 - 65] = token_block_bits[length - 1 - 28]
        token_block_bits[length - 1 - 64] = token_block_bits[length - 1 - 27]
        token_block_bits[length - 1 - 28] = token_class_bits[0]
        token_block_bits[length - 1 - 27] = token_class_bits[1]
        return {
            "success": True,
            "message": "".join(token_block_bits)
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Transposition error: {str(e)}"
        }

def process_token(token_block_bin: str, decoding_key_bin: str):
    try:
        key_bytes = bin_str_to_bytes(decoding_key_bin)
        data_bytes = bin_str_to_bytes(token_block_bin)
        enc_result = encrypt(data_bytes, key_bytes)
        if not enc_result["success"]:
            return {"success": False, "message": enc_result["message"]}
        encrypted_bin_str = bytes_to_bin_str(enc_result["message"])
        cls = dec_to_bin(token_class, 2)
        
        # Insert class bits and perform transposition
        trans_result = insert_and_transposition_class_bits(encrypted_bin_str, cls)
        if not trans_result["success"]:
            return {"success": False, "message": trans_result["message"]}
        final_66_bit_token = trans_result["message"]
        print(f"Final 66-bit token: {final_66_bit_token}")
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
