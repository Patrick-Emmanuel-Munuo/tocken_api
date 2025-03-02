from flask import Flask, jsonify
import threading
import time
from flask_cors import CORS  # Importing flask_cors to enable CORS
from datetime import datetime
import math
import logging

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


def dec_to_bin(decimal, length):
    """Converts a decimal number to binary and pads it to a specific length."""
    return bin(decimal)[2:].zfill(length)


def bin_to_hex(binary_str):
    """Converts binary string to hex."""
    return hex(int(binary_str, 2))[2:].upper()


def hex_to_byte_array(hex_str):
    """Converts hex string to byte array."""
    return binascii.unhexlify(hex_str)


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


def get_mantissa(exponent, amount):
    """Calculates the mantissa given the exponent and complemented amount."""
    if exponent == 0:
        return amount
    else:
        rhs_sum = 0
        for i in range(1, exponent + 1):
            rhs_sum += int(math.pow(2, 14) * math.pow(10, i - 1))
        return (amount - rhs_sum) // int(math.pow(10, exponent))


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


def get_amount_block():
    """Returns a 16-bit binary for the amount block."""
    complemented_amount = int(utility_amount * 10)
    exponent = get_exponent(complemented_amount)
    mantissa = get_mantissa(exponent, complemented_amount)
    return dec_to_bin(exponent, 2) + dec_to_bin(mantissa, 14)


def calculate_crc16(datablock):
    """Calculates the CRC and returns it in a 16-bit binary form."""
    crc = 0xFFFF
    for bt in datablock:
        crc ^= bt & 0x00FF
        for _ in range(8):
            if crc & 1:
                crc ^= 0xA001
            crc >>= 1
    return dec_to_bin(crc, 16)


def build_string(*vars):
    """Builds a string by passing any number of arguments."""
    return ''.join(vars)


def get_crc_block(initial_50_bit_block):
    """Returns the 16-bit CRC for the 50-bit initial block."""
    hex_str = bin_to_hex(initial_50_bit_block)
    hex_str = hex_str.zfill(14)  # Pad to 56 bits (14 hex characters)
    byte_array = hex_to_byte_array(hex_str)
    return calculate_crc16(byte_array)


def build_64_bit_token_block():
    """Builds the 64-bit token block that proceeds to encryption."""
    cls = get_class_block()
    subclass = get_subclass_block()
    rnd_block = get_rnd_block()
    tid_block = get_tid_block()
    amount_block = get_amount_block()
    crc_block = get_crc_block(build_string(cls, subclass, rnd_block, tid_block, amount_block))
    token_64_bit_block = build_string(subclass, rnd_block, tid_block, amount_block, crc_block)

    print(f"Token Class Binary: {cls}")
    print(f"Token Subclass Binary: {subclass}")
    print(f"Token RND Binary: {rnd_block}")
    print(f"Token TID Binary: {tid_block}")
    print(f"Token Amount Binary: {amount_block}")
    print(f"Token CRC Binary: {crc_block}")
    print(f"64-bit Block ready for encryption: {token_64_bit_block}")

@app.route('/get_tocket', methods=['GET'])
def generate_key():
    """Route to generate the 'tocket'."""
    try:
        unit_block = get_amount_block(32.5)  # Get the amount block for the utility amount
        # Return the data in the requested format
        return jsonify({
            "success": True,
            "message": unit_block
        })

    except Exception as e:
        # Log the error and return a failure response
        logging.error(f"Error in get_tocket function: {e}")
        return jsonify({
            "success": False,
            "message": f"Failed to get tocket: {str(e)}"
        }), 500


def run_flask_app():
    """Function to run the Flask app."""
    try:
        port = int(os.environ.get("PORT", 1000))  # Set the port dynamically from the environment or default to 1000
        app.run(host='0.0.0.0', port=port, debug=False)  # Set debug=False for production environment
    except Exception as e:
        logging.error(f"Error in run_flask_app function: {e}")


if __name__ == "__main__":
    try:
        logging.info("Flask app is running.")
        # Give the Flask app time to start
        time.sleep(1)

        # Run the Flask app in a separate thread (optional)
        threading.Thread(target=run_flask_app).start()

    except Exception as e:
        # Log any error that occurs during app initialization
        logging.error(f"Error in main block: {e}")
        time.sleep(1)
