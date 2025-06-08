from flask import Flask, jsonify, request
from flask_cors import CORS
from datetime import datetime, timedelta
import math
import binascii
import base64
import random
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import math


# Initialize Flask app and CORS
app = Flask(__name__)
CORS(app)

# Constants and globals
token_class = 0
token_sub_class = 0
base_date = datetime(2025, 5, 5, 0, 0, 0)
#025-06-07 15:28:00
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


def build_string(*args):
    """Concatenate strings."""
    return ''.join(args)

def decrypt(data: bytes, key: bytes):
    """
    Decrypt exactly 8 bytes of data using 3DES (ECB mode, no padding).
    :param data: exactly 8 bytes encrypted data
    :param key: 16 or 24 bytes key
    :return: dict with success bool and message (decrypted bytes or error)
    """
    if len(data) != 8:
        return {
            "success": False,
            "message": f"Data is {len(data)} must be exactly 8 bytes."
        }
    if len(key) not in (16, 24):
        return {
            "success": False,
            "message": f"Key is {len(key)} must be either 16 or 24 bytes for 3DES."
        }
    try:
        key = DES3.adjust_key_parity(key)
        cipher = DES3.new(key, DES3.MODE_ECB)
        decrypted = cipher.decrypt(data)  # no unpadding, data size fixed to 8 bytes
        return {
            "success": True,
            "message": decrypted
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Decryption failed: {str(e)}"
        }
   
def transposition_and_remove_class_bits_old(token_number_binary: str):
    try:
        block_bits = list(token_number_binary)
        length = len(block_bits)
        # Validate the input length
        if length < 66:
            return {
                "success": False,
                "message": "Token binary must be at least 66 bits long to reverse transposition."
            }
        # Restore original bits positions
        # Save bits that were swapped in the original function
        pos_65 = length - 1 - 65
        pos_64 = length - 1 - 64
        pos_28 = length - 1 - 28
        pos_27 = length - 1 - 27
        # Reverse the transposition:
        # Put original bits back at pos_28 and pos_27 (which currently hold token_class bits)
        block_bits[pos_28] = saved_65
        block_bits[pos_27] = saved_64

        # Extract the token class bits (which were inserted at the front)
        token_class_bits = block_bits[0:2]

        # Remove the token class bits from the front to get original encrypted token block
        restored_block = block_bits[2:]
        return {
            "success": True,
            "message": restored_block
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Error in transposition and class bits removal: {str(e)}"
        }

def transposition_and_remove_class_bits(token_number_binary: str):
    try:
        block_bits = list(token_number_binary)
        length = len(block_bits)
        if length < 66:
            return {
                "success": False,
                "message": "Token binary must be at least 66 bits long to reverse transposition."
            }
        pos_65 = length - 1 - 65
        pos_64 = length - 1 - 64
        pos_28 = length - 1 - 28
        pos_27 = length - 1 - 27
        # Save the bits at pos_65 and pos_64 (which were overwritten originally)
        saved_65 = block_bits[pos_65]
        saved_64 = block_bits[pos_64]
        # Reverse the transposition:
        # Put original bits back at pos_28 and pos_27 (which currently hold token_class bits)
        block_bits[pos_28] = saved_65
        block_bits[pos_27] = saved_64
        # Extract the token class bits (which were inserted at the front)
        token_class_bits = block_bits[0:2]
        # Remove the token class bits from the front to get original encrypted token block
        restored_block = block_bits[2:]
        return {
            "success": True,
            "message": "".join(restored_block),
            "class": "".join(token_class_bits)
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Error in transposition and class bits removal: {str(e)}"
        }

def decrypt_and_parse_token(encrypted_token_bin: str, decoding_key_bin: str):
    try:
        key_bytes = bin_str_to_bytes(decoding_key_bin)
        trans_result = transposition_and_remove_class_bits(encrypted_token_bin)
        if not trans_result["success"]:
            return {
                "success": False,
                "message": trans_result["message"]
                }
        original_64_bit = trans_result["message"]
        original_64_bit = original_64_bit[:64]
        if len(original_64_bit) != 64:
            raise ValueError("Token block must be exactly 64 bits after transposition and class bits removal.")
        encrypted_bytes = bin_str_to_bytes(original_64_bit)
        enc_result = decrypt(encrypted_bytes, key_bytes)
        if not enc_result["success"]:
            return {"success": False, "message": enc_result["message"]}
        
        decrypted_bin = bytes_to_bin_str(enc_result["message"])
        if len(decrypted_bin) != 64:
            raise ValueError("Token block must be exactly 64 bits.")
        #cls = decrypted_bin[0:2]#0,1
        rnd_block = decrypted_bin[0:3]#0,1
        tid_block = decrypted_bin[3:25] #1,
        amount_block = decrypted_bin[25:48]
        crc_block = decrypted_bin[48:64]

        rnd_val = int(rnd_block, 2)
        tid_minutes = int(tid_block, 2)
        # Units decoding
        units_result = decode_units(amount_block)
        if not units_result["success"]:
            raise Exception(units_result["message"])
        units = units_result["message"]
        crc_val = int(crc_block, 2)

        # Set base date and compute time-related values
        issue_time = base_date + timedelta(minutes=tid_minutes)
        token_expired_date = issue_time + timedelta(days=365)
        time_now = datetime.now()

        # CRC validation
        data_bin = decrypted_bin[:48]
        data_hex = bin_to_hex(data_bin).zfill(14)
        data_bytes = hex_to_byte_array(data_hex)
        crc_result = calculate_crc16(data_bytes)
        if not crc_result["success"]:
            raise Exception(crc_result["message"])
        crc_calc_bin = crc_result["message"].zfill(16)
        crc_in_token_bin = decrypted_bin[48:64].zfill(16)

        if crc_calc_bin != crc_in_token_bin:
            raise ValueError("CRC mismatch - invalid token data")

        # Validation checks
        if time_now - issue_time > timedelta(days=365):
            raise ValueError("Token expired")
        if issue_time < base_date or issue_time > time_now + timedelta(days=1):
            raise ValueError("Change meter base date")
        result = {
            "random": rnd_val,
            "identifier_minutes": tid_minutes,
            "issue_datetime": issue_time.strftime("%Y-%m-%d %H:%M:%S"),
            "base_date": base_date.strftime("%Y-%m-%d %H:%M:%S"),
            "expired_date": token_expired_date.strftime("%Y-%m-%d %H:%M:%S"),
            "units": float(units),
            "crc": crc_val,
        }
        return {
            "success": True,
            "message": result
        }
    except Exception as e:
        return {
            "success": False,
            "message": {
                "status": f"Failed  parse token: {str(e)}"
            }
        }

@app.route("/decrypt_token", methods=["GET"])
def api_decrypt():
    try:
        token_numbers = request.args.get("token")
        if not token_numbers:
            return jsonify({"success": False, "message": "Token parameter is missing"}), 400
        
        # Remove dashes and validate format
        token = token_numbers.replace('-', '')
        if len(token) != 20 or not token.isdigit():
            return jsonify({"success": False, "message": "Invalid token format. Must be 20 digits (dashes allowed)."}), 400
        
        # Convert token to binary string with 66 bits
        token_bin = bin(int(token))[2:].zfill(66)
        # Generate decoding key
        decoder_key_result = generate_decoder_key()
        if not decoder_key_result["success"]:
            return jsonify({"success": False, "message": decoder_key_result["message"]}), 500
        
        decoding_key_bin = decoder_key_result["message"]
        key_bytes = bin_str_to_bytes(decoding_key_bin)
        
        if len(key_bytes) != 16:
            return jsonify({"success": False, "message": "Decoding key length invalid (expected 16 bytes)."}), 500

        # Decrypt and parse token
        result = decrypt_and_parse_token(token_bin, decoding_key_bin)
        if not result["success"]:
            return jsonify({"success": False, "message": result["message"]}), 400
        token_info = result["message"]
        return jsonify({
            "success": True,
            "message": {
                **token_info,
                "status": "Token successfully decrypted and parsed."
            }
        }), 200
    except ValueError as ve:
        return jsonify({
            "success": False,
            "message": f"api_decrypt Validation error: {str(ve)}"
        }), 400
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"api_decrypt An unexpected error occurred: {str(e)}"
        }), 500
if __name__ == "__main__":
    app.run(debug = True, port = 1010)
