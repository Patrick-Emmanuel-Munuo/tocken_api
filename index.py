from flask import Flask, jsonify, request
import threading
import time
from flask_cors import CORS
from datetime import datetime
import math
import logging
import binascii
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Initialize Flask app and Limiter
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Constants
token_class = 0
token_sub_class = 0
random = 7
utility_amount = 32.5
issue_date_time = datetime(2021, 7, 30, 8, 50, 30)
base_date = datetime(1993, 1, 1, 0, 0, 0)
# CRC-16 Modbus polynomial: 0x8005
CRC_POLYNOMIAL = 0x8005

# Function to convert a binary string to decimal (int)
def bin_to_dec(binary: str) -> int:
    return int(binary, 2)


# Function to convert decimal to binary, with padding to specified bits
def dec_to_bin(decimal: int, num_bits: int) -> str:
    binary = bin(decimal)[2:]  # remove the '0b' prefix
    return binary.zfill(num_bits)


# Function to convert a binary string to a hex string
def bin_to_hex(binary: str) -> str:
    return hex(int(binary, 2))[2:].upper()


# Function to convert hex to binary with padding to a specified length
def hex_to_bin(hex_str: str, num_bits: int) -> str:
    binary = bin(int(hex_str, 16))[2:]  # remove the '0b' prefix
    return binary.zfill(num_bits)
# Ensure `get_exponent` function is defined properly
def get_exponent(amount):
    """Returns the exponent depending on the complemented amount."""
    if amount <= 16383:
        return 0
    elif amount <= 180214:
        return 1
    elif amount <= 1818524:
        return 2
    else:
        return 3


# Ensure `get_mantissa` and other necessary helper functions are defined
def get_mantissa(exponent, amount):
    """Calculates the mantissa given the exponent and complemented amount."""
    if exponent == 0:
        return amount
    else:
        rhs_sum = 0
        for i in range(1, exponent + 1):
            rhs_sum += int(math.pow(2, 14) * math.pow(10, i - 1))
        return (amount - rhs_sum) // int(math.pow(10, exponent))


def dec_to_bin(decimal, length):
    """Converts a decimal number to binary and pads it to a specific length."""
    return bin(decimal)[2:].zfill(length)


# Function to build a key from a byte array (should be 8 bytes long for DES)
def build_key(key_bytes: bytes) -> bytes:
    if len(key_bytes) != 8:
        raise ValueError("Key must be exactly 8 bytes long.")
    return key_bytes


# Function to encrypt data using DES (ECB mode)
def encrypt(source: bytes, secret_key: bytes) -> bytes:
    cipher = DES.new(secret_key, DES.MODE_ECB)  # ECB mode encryption
    padded_data = pad(source, DES.block_size)
    return cipher.encrypt(padded_data)


# Function to decrypt data using DES (ECB mode)
def decrypt(encrypted: bytes, secret_key: bytes) -> bytes:
    cipher = DES.new(secret_key, DES.MODE_ECB)  # ECB mode decryption
    decrypted_data = cipher.decrypt(encrypted)
    return unpad(decrypted_data, DES.block_size)


# Function to insert and transpose class bits into the encrypted token
def insert_and_transposition_class_bits(token_block: str, token_class: str) -> str:
    with_class_bits = token_class + token_block
    token_class_bits = list(token_class)
    token_block_bits = list(with_class_bits)
    
    # Transposing the class bits
    token_block_bits[len(with_class_bits)-1-65] = token_block_bits[len(with_class_bits)-1-28]
    token_block_bits[len(with_class_bits)-1-64] = token_block_bits[len(with_class_bits)-1-27]
    token_block_bits[len(with_class_bits)-1-28] = token_class_bits[0]
    token_block_bits[len(with_class_bits)-1-27] = token_class_bits[1]

    return ''.join(token_block_bits)


# Function to convert a 66-bit token binary to a 20-digit utility token
def convert_to_token_number(token_block: str) -> str:
    token_number = bin_to_dec(token_block)
    token_number_str = str(token_number).zfill(20)

    # Formatting the token number in groups of 4 digits with hyphens
    token_parts = [token_number_str[i:i+4] for i in range(0, len(token_number_str), 4)]
    return '-'.join(token_parts)


# Main function to simulate TokenEncryptor behavior
def process_token(token_block: str, token_class: str, decoder_key: str) -> str:
    # Convert the decoder key to a 8-byte binary and then to a byte array
    decoder_key_bytes = bin_to_hex(decoder_key)
    decoder_key_bytes = bytes.fromhex(decoder_key_bytes)

    # Encrypt the token block with the decoder key
    encrypted_token = encrypt(bytes.fromhex(token_block), build_key(decoder_key_bytes))
    
    # Convert encrypted token to binary string (returning with correct padding)
    encrypted_token_bin = bin(int(binascii.hexlify(encrypted_token), 16))[2:].zfill(len(token_block) * 4)

    # Insert and transpose class bits into the encrypted token
    token_with_class_bits = insert_and_transposition_class_bits(encrypted_token_bin, token_class)

    # Convert the final token to a 20-digit utility token
    utility_token = convert_to_token_number(token_with_class_bits)
    
    return utility_token


def calculate_crc16(data: bytes) -> str:
    """
    CRC-16 Modbus calculation method.
    
    :param data: The input data as a byte array.
    :return: CRC-16 value as a 4-digit hexadecimal string.
    """
    crc = 0xFFFF  # Initial value
    for byte in data:
        crc ^= byte & 0xFF  # XOR with byte data
        for _ in range(8):  # Process each bit
            if (crc & 0x8000) != 0:  # Check if the MSB is 1
                crc = (crc << 1) ^ CRC_POLYNOMIAL
            else:
                crc <<= 1
            crc &= 0xFFFF  # Ensure CRC remains 16 bits
    return dec_to_bin(crc, 14)  # Return CRC as a 4-digit uppercase hexadecimal string


def build_64_bit_token_block(units):
    """Builds the 64-bit token block that proceeds to encryption."""
    
    # Helper functions (you can move these to separate functions if necessary)
    def get_class_block():
        """Returns a 2-bit binary for the token class."""
        return dec_to_bin(token_class, 2)

    def get_subclass_block():
        """Returns a 4-bit binary for the token subclass."""
        return dec_to_bin(token_sub_class, 4)

    def get_rnd_block():
        """Returns a 4-bit binary for the random number."""
        return dec_to_bin(random, 4)

    def get_tid_block():
        """Returns a 24-bit binary for the Token Identifier."""
        minutes = int((issue_date_time - base_date).total_seconds() // 60)
        return dec_to_bin(minutes, 24)

    def get_amount_block(units):
        """Returns a 16-bit binary for the amount block."""
        complemented_amount = int(units * 10)
        exponent = get_exponent(complemented_amount)
        mantissa = get_mantissa(exponent, complemented_amount)
        return dec_to_bin(exponent, 2) + dec_to_bin(mantissa, 14)

    def get_crc_block(initial_50_bit_block):
        """Returns the 16-bit CRC for the 50-bit initial block."""
        hex_str = bin_to_hex(initial_50_bit_block)
        hex_str = hex_str.zfill(14)  # Pad to 56 bits (14 hex characters)
        byte_array = hex_to_byte_array(hex_str)
        return calculate_crc16(byte_array)

    # Build the 64-bit token block
    cls = get_class_block()
    subclass = get_subclass_block()
    rnd_block = get_rnd_block()
    tid_block = get_tid_block()
    amount_block = get_amount_block(units)
    
    # Concatenate the blocks
    initial_50_bit_block = build_string(cls, subclass, rnd_block, tid_block, amount_block)
    
    # Calculate CRC for the 50-bit block
    crc_block = get_crc_block(initial_50_bit_block)
    
    # Final 64-bit token block
    token_64_bit_block = build_string(subclass, rnd_block, tid_block, amount_block, crc_block)

    result = {
        "units": units,
        "cls": cls,
        "subclass": subclass,
        "rnd_block": rnd_block,
        "tid_block": tid_block,
        "amount_block": amount_block,
        "crc_block": crc_block,
        "token_64_bit_block": token_64_bit_block,
    }

    return result

# Ensure that build_string function is defined
def build_string(*vars):
    """Builds a string by passing any number of arguments."""
    return ''.join(vars)

def hex_to_byte_array(hex_str):
    """Converts a hex string to a byte array."""
    return bytes.fromhex(hex_str)


def get_crc_block(initial_50_bit_block):
    """Returns the 16-bit CRC for the 50-bit initial block."""
    hex_str = bin_to_hex(initial_50_bit_block)
    hex_str = hex_str.zfill(14)  # Pad to 56 bits (14 hex characters)
    byte_array = hex_to_byte_array(hex_str)
    return calculate_crc16(byte_array)


# Example usage of the updated code
def process_token(token_block: str, token_class: str, decoder_key: str) -> str:
    # Convert the decoder key to a 8-byte binary and then to a byte array
    decoder_key_bytes = bin_to_hex(decoder_key)
    decoder_key_bytes = bytes.fromhex(decoder_key_bytes)

    # Encrypt the token block with the decoder key
    encrypted_token = encrypt(bytes.fromhex(token_block), build_key(decoder_key_bytes))

    # Convert encrypted token to binary string (returning with correct padding)
    encrypted_token_bin = bin(int(binascii.hexlify(encrypted_token), 16))[2:].zfill(len(token_block) * 4)

    # Insert and transpose class bits into the encrypted token
    token_with_class_bits = insert_and_transposition_class_bits(encrypted_token_bin, token_class)

    # Convert the final token to a 20-digit utility token
    utility_token = convert_to_token_number(token_with_class_bits)

    return utility_token

# Define routes and other logic here
@app.route('/', methods=['GET'])
def index_root():
    """Route to check if the server is running."""
    try:
        return jsonify({
        "success": True,
        "message": 'Server is running.'
        })
    except Exception as e:
        logging.error(f"Error  function: {e}")
        return jsonify({
            "success": False,
            "message": f"Failed to get : {str(e)}"
        }), 500


@app.route('/get_tocket', methods=['GET'])
def generate_key():
    """Route to generate the 'tocket'."""
    try:
        units = request.args.get('amount', default=32.5, type=float)  # Allow amount input
        unit_block = build_64_bit_token_block(units)  # Get the amount block for the utility amount
        
        return jsonify({
            "success": True,
            "message": unit_block
        })

    except Exception as e:
        logging.error(f"Error in get_tocket function: {e}")
        return jsonify({
            "success": False,
            "message": f"Failed to get tocket: {str(e)}"
        }), 500


# Run the Flask application
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=1000, debug=False)  # Set debug=False for production environment

