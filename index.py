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

vending_key_base64 = "M+eSQjQLvW2r+7Zz8RrHaAxVxYE="  # base64 encoded 20-byte key
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


def generate_decoder_key():
    """Generate binary string for decoder key based on constants."""
    def convert(number_str, bit_length):
        number_int = int(number_str)
        return format(number_int, f'0{bit_length}b')

    key_type_bin = convert(key_type, 4)
    supply_group_bin = convert(supply_group_code, 16)
    tariff_index_bin = convert(tariff_index, 4)
    key_revision_bin = convert(key_revision_number, 8)
    drn_bin = convert(decoder_reference_number, 32)

    data_block_bin = key_type_bin + supply_group_bin + tariff_index_bin + key_revision_bin + drn_bin
    # Should be 64 bits total (check bits)
    return data_block_bin

def get_mantissa(units):
    """Calculate exponent and mantissa from  amount."""
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
    if exponent == 0:
        mantissa = amount
    else:
        rhs_sum = sum(int(2**14 * 10**(i - 1)) for i in range(1, exponent + 1))
        mantissa = round((amount - rhs_sum) / (10**exponent))  # Use round instead of //
    mantissa = int(mantissa + 0.5)
    return exponent, mantissa

def decode_units(exponent, mantissa):
    """
    Reconstructs unit value from exponent and mantissa.
    """
    try:
     import math
     if exponent == 0:
         amount = mantissa
     else:
        rhs_sum = sum(int(math.pow(2, 14) * math.pow(10, i - 1)) for i in range(1, exponent + 1))
        amount = mantissa * (10 ** exponent) + rhs_sum
     return round(amount / 10.0, 2)
    except Exception as e:
        raise ValueError(f"Failed to decode units: {e}")


def calculate_crc16(data: bytes, poly=0x1021, init_crc=0xFFFF) -> str:
    crc = init_crc
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if (crc & 0x8000):
                crc = (crc << 1) ^ poly
            else:
                crc <<= 1
            crc &= 0xFFFF
    return format(crc, '016b')


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
    exponent, mantissa = get_mantissa(units)
    amount_block = get_amount_block(exponent, mantissa)
    initial_50_bit_block = build_string(subclass, rnd_block, tid_block, amount_block)

    # Calculate CRC for the 50-bit block
    hex_str = bin_to_hex(initial_50_bit_block)
    hex_str = hex_str.zfill(14)  # Pad to 56 bits (14 hex characters)
    byte_array = hex_to_byte_array(hex_str)
    crc_block = calculate_crc16(byte_array)

    token_64_bit_block = build_string(initial_50_bit_block, crc_block)

    print("Full encoded token Block (bin):", token_64_bit_block)
    print("Full encoded token Block (hex):", bin_to_hex(token_64_bit_block))
    print("Total bits:", len(token_64_bit_block))

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

def encrypt(data: bytes, key: bytes) -> bytes:
    """Encrypt 8-byte data with 8-byte key using DES ECB."""
    if len(data) != 8 or len(key) != 8:
        raise ValueError("Both data and key must be exactly 8 bytes.")
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(data)


def decrypt(encrypted: bytes, key: bytes) -> bytes:
    """Decrypt 8-byte encrypted data with 8-byte key using DES ECB."""
    if len(encrypted) != 8 or len(key) != 8:
        raise ValueError("Both encrypted data and key must be exactly 8 bytes.")
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.decrypt(encrypted)


def convert_to_token_number(token_block_bin: str) -> str:
    """Convert 66-bit token binary to 20-digit utility token string."""
    token_number = int(token_block_bin, 2)
    token_number_str = str(token_number).zfill(20)
    token_parts = [token_number_str[i:i + 4] for i in range(0, len(token_number_str), 4)]
    return '-'.join(token_parts)


def process_token(token_block_bin: str, decoding_key_bin: str) -> str:
    """Encrypt the token_block with the decoding_key and return formatted utility token."""
    key_bytes = bin_str_to_bytes(decoding_key_bin)
    data_bytes = bin_str_to_bytes(token_block_bin)

    encrypted_bytes = encrypt(data_bytes, key_bytes)
    encrypted_bin_str = bytes_to_bin_str(encrypted_bytes)
    utility_token = convert_to_token_number(encrypted_bin_str)
    return utility_token


def parse_token_block(token_64_bit_block: str, verbose=False):
    """Parse a 64-bit token block and extract fields."""
    if len(token_64_bit_block) != 64:
        raise ValueError("Token block must be exactly 64 bits.")

    subclass = token_64_bit_block[0:4]
    rnd_block = token_64_bit_block[4:8]
    tid_block = token_64_bit_block[8:32]
    amount_exponent = token_64_bit_block[32:34]
    amount_mantissa = token_64_bit_block[34:48]
    crc_block = token_64_bit_block[48:64]

    subclass_val = int(subclass, 2)
    rnd_val = int(rnd_block, 2)
    tid_minutes = int(tid_block, 2)
    exponent = int(amount_exponent, 2)
    mantissa = int(amount_mantissa, 2)
    crc_val = int(crc_block, 2)

    issue_time = base_date + timedelta(minutes=tid_minutes)
    units = decode_units(exponent, mantissa)
    result = {
        "subclass": subclass_val,
        "random": rnd_val,
        "token_identifier_minutes": tid_minutes,
        "token_issue_datetime": issue_time.strftime("%Y-%m-%d %H:%M:%S"),
        "amount_exponent": exponent,
        "amount_mantissa": mantissa,
        "units": units,
        "crc": crc_val,
    }
    if verbose:
        print(result)
    return result


def decrypt_and_parse_token(encrypted_token_bin: str, decoding_key_bin: str, verbose=False):
    """Decrypt encrypted token bin string with key, then parse the decrypted token block."""
    key_bytes = bin_str_to_bytes(decoding_key_bin)
    encrypted_bytes = bin_str_to_bytes(encrypted_token_bin)
    decrypted_bytes = decrypt(encrypted_bytes, key_bytes)
    decrypted_bin = bytes_to_bin_str(decrypted_bytes)

    if verbose:
        print(f"Decrypted binary: {decrypted_bin}")

    parsed = parse_token_block(decrypted_bin, verbose=verbose)

    # Recalculate CRC on first 48 bits (everything except last 16 bits)
    data_bin = decrypted_bin[:48]
    data_hex = bin_to_hex(data_bin).zfill(14)  # 48 bits = 12 hex chars
    data_bytes = hex_to_byte_array(data_hex)

    crc_calc_bin = calculate_crc16(data_bytes).zfill(16)
    crc_in_token_bin = decrypted_bin[48:64].zfill(16)
    if verbose:
        print(f"Token CRC bits: {crc_in_token_bin}")
        print(f"Calculated CRC bits: {crc_calc_bin}")
    if crc_calc_bin != crc_in_token_bin:
        raise ValueError("CRC mismatch - invalid token data")
    # Additional validations (optional)
    now = datetime.utcnow()
    token_issue_time = datetime.strptime(parsed["token_issue_datetime"], "%Y-%m-%d %H:%M:%S")
    if token_issue_time < base_date or token_issue_time > now + timedelta(days=1):
        raise ValueError("Token issue date/time is out of valid range")

    return parsed

@app.route("/decrypt_token", methods=["GET"])
def api_decrypt():

    try:
        token_numbers = request.args.get("token")
        if not token_numbers:
            return jsonify({"success": False, "message": "Token parameter is missing"}), 400
        token = token_numbers.replace('-', '')
        if len(token) != 20 or not all(c.isdigit() or c == '-' for c in token_numbers):
            return jsonify({"success": False, "message": "Invalid token format"}), 400
        token_bin = bin(int(token))[2:]
        decoding_key_bin = generate_decoder_key() #request.args.get("key")
        result = decrypt_and_parse_token(token_bin, decoding_key_bin, verbose=True)
        return jsonify({
            "success": True,
            "message": "Token successfully decrypted and parsed.",
            "data": result
        }), 200
    except ValueError as ve:
        return jsonify({"success": False, "message": f"Validation error: {str(ve)}"}), 400
    except Exception as e:
        return jsonify({"success": False, "message": f"An error occurred: {str(e)}"}), 500

@app.route("/generate_token", methods=["GET"])
def api_encrypt():
    #data = request.json
    units_str = request.args.get("units", "0")
    units_float = float(units_str)
    units = int(units_float * 10) / 10
    try:
        # Generate decoder key binary string
        decoder_key_bin = generate_decoder_key()
        # Build token block for given units
        token_data = build_64_bit_token_block(float(units))
        token_64_bit_block = token_data["token_64_bit_block"]
        # Encrypt and get utility token
        utility_token = process_token(token_64_bit_block, decoder_key_bin)
        return jsonify({"status": "success", "utility_token": utility_token})
    except ValueError as ve:
        return jsonify({"success": False, "message": f"Validation error: {str(ve)}"}), 400
    except Exception as e:
        return jsonify({"success": False, "message": f"An error occurred: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(debug=True, port=1000)
