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
base_date = datetime(2022, 1, 1, 0, 0, 0)#.strftime("%Y-%m-%d %H:%M:%S")
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

def decode_units(exponent, mantissa):
    """
    Reconstructs the original units value from the exponent and mantissa.
    Assumes encoding was done using:
        amount = rhs_sum + mantissa * (10 ** exponent)
        units = amount / 100
    """
    try:
        # Use float sum to avoid truncation errors
        rhs_sum = sum(int(math.pow(2, 14) * math.pow(10, i - 1)) for i in range(1, exponent + 1))
        amount = mantissa * (10 ** exponent) + rhs_sum
        # Convert amount back to float units (divide by 100)
        units = round(amount / 100, 2)
        return {
            "success": True,
            "message": units
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Failed to decode units: {str(e)}"
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
   
def transposition_and_remove_class_bits(token_number_binary: str) -> str:
    block_bits = list(token_number_binary)
    length = len(token_number_binary)
    
    # Restore original bits positions
    block_bits[length - 1 - 28] = block_bits[0]
    block_bits[length - 1 - 27] = block_bits[1]
    
    # Remove the first two bits (class bits)
    restored_block = "".join(block_bits)[2:]
    return restored_block

def decrypt_and_parse_token(encrypted_token_bin: str, decoding_key_bin: str):
 try:
    """Decrypt encrypted token bin string with key, then parse the decrypted token block."""
    key_bytes = bin_str_to_bytes(decoding_key_bin)
    original_64_bit = transposition_and_remove_class_bits(encrypted_token_bin)
    encrypted_bytes = bin_str_to_bytes(original_64_bit)
    enc_result = decrypt(encrypted_bytes, key_bytes)
    if not enc_result["success"]:
        return {"success": False, "message": enc_result["message"]}
    decrypted_bin = bytes_to_bin_str(enc_result["message"])
    """Parse a 64-bit token block and extract fields."""
    if len(decrypted_bin) != 64:
        raise ValueError("Token block must be exactly 64 bits.")
    subclass = decrypted_bin[0:4]
    rnd_block = decrypted_bin[4:8]
    tid_block = decrypted_bin[8:32]
    amount_exponent = decrypted_bin[32:34]
    amount_mantissa = decrypted_bin[34:48]
    crc_block = decrypted_bin[48:64]
    subclass_val = int(subclass, 2)
    rnd_val = int(rnd_block, 2)
    tid_minutes = int(tid_block, 2)
    exponent = int(amount_exponent, 2)
    mantissa = int(amount_mantissa, 2)
    crc_val = int(crc_block, 2)
    issue_time = base_date + timedelta(minutes=tid_minutes)
    units_result = decode_units(exponent, mantissa)
    if not units_result["success"]:
        raise Exception(units_result["message"])
    units = units_result["message"]
    token_expired_date = base_date
    result = {
        "subclass": subclass_val,
        "random": rnd_val,
        "token_identifier_minutes": tid_minutes,
        "token_issue_datetime": issue_time.strftime("%Y-%m-%d %H:%M:%S"),
        "base_date":base_date,
        "token_expired_date":token_expired_date,
        "amount_exponent": exponent,
        "amount_mantissa": mantissa,
        "units": units,
        "crc": crc_val,
    }
    # Recalculate CRC on first 48 bits (everything except last 16 bits)
    data_bin = decrypted_bin[:48]
    data_hex = bin_to_hex(data_bin).zfill(14)  # 48 bits = 12 hex chars
    data_bytes = hex_to_byte_array(data_hex)

    # Calculate CRC16 on the data bytes
    crc_result = calculate_crc16(data_bytes)
    if not crc_result["success"]:
        raise Exception(crc_result["message"])
    crc_calc_bin = crc_result["message"].zfill(16)
    crc_in_token_bin = decrypted_bin[48:64].zfill(16)
    if crc_calc_bin != crc_in_token_bin:
        raise ValueError("CRC mismatch - invalid token data")
    
    # Additional validations (optional)
    time_now =  datetime.now()
    token_issue_time = datetime.strptime(result["token_issue_datetime"], "%Y-%m-%d %H:%M:%S")
    # Check if the token is older than 1 year
    if time_now - token_issue_time > timedelta(days=365):
        raise ValueError("Token expired")
    # Check if token is before base date or too far in the future
    if token_issue_time < base_date or token_issue_time > time_now + timedelta(days=1):
        raise ValueError("Change meter base date")
    return {
        "success": True,
        "message": result
        }
 except Exception as e:
     return {
         "success": False,
         "message": f"Failed to decode units: {str(e)}"
         }

@app.route("/decrypt_token", methods=["GET"])
def api_decrypt():
    try:
        token_numbers = request.args.get("token")
        if not token_numbers:
            return jsonify({"success": False, "message": "Token parameter is missing"}), 400
        token = token_numbers.replace('-', '')
        if len(token) != 20 or not all(c.isdigit() or c == '-' for c in token_numbers):
            return jsonify({"success": False, "message": "Invalid token format"}), 400
        token_bin = bin(int(token))[2:].zfill(66)
        decoder_key_result = generate_decoder_key()
        if not decoder_key_result["success"]:
            return jsonify({"success": False, "message": decoder_key_result["message"]}), 500
        decoding_key_bin = decoder_key_result["message"]
        key_bytes = bin_str_to_bytes(decoding_key_bin)
        if len(key_bytes) != 16:
            return {"success": False, "message": "Decoding key is not 8 bytes"}
        result = decrypt_and_parse_token(token_bin, decoding_key_bin)
        return jsonify({
            "success": True,
            "message": {
                #**result["message"] ,
                "status": "Token successfully decrypted and parsed.",
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
            "message": f"api_decrypt An error occurred: {str(e)}"
        }), 500
if __name__ == "__main__":
    app.run(debug = True, port = 1010)
