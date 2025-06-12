import requests
import random
import time
import json

API_URL = "http://127.0.0.1:1010/decrypt_token"
TOKENS_JSON_FILE = "C:\\Users\\Eng VarTrick\\Documents\\test_tokens.json"  # Windows path
LOG_TXT_FILE = "C:\\Users\\Eng VarTrick\\Documents\\test_log.txt"


def generate_random_20_digit_token():
    return ''.join(str(random.randint(0, 9)) for _ in range(20))

def send_request(token):
    try:
        params = {"token": token}
        response = requests.get(API_URL, params=params, timeout=5)
        #response.raise_for_status()
        data = response.json()
        return data.get("success", False)
    except Exception as e:
        print(f"API request error for token {token}: {e}")
        return False

def save_tokens_to_json(tokens):
    try:
        with open(TOKENS_JSON_FILE, 'w') as f:
            json.dump(tokens, f, indent=2)
    except Exception as e:
        print(f"Error saving tokens JSON: {e}")

def append_log_to_txt(log_text):
    try:
        with open(LOG_TXT_FILE, 'a') as f:
            f.write(log_text + "\n")
    except Exception as e:
        print(f"Error writing to log file: {e}")

def run_test():
    total_requests = 0
    pass_count = 0
    fail_count = 0
    all_tokens = []  # only tokens (strings)

    while True:
        start_time = time.time()

        tokens = [generate_random_20_digit_token() for _ in range(20)]

        for token in tokens:
            result = send_request(token)
            all_tokens.append(token)

            if result:
                pass_count += 1
            else:
                fail_count += 1

        total_requests += len(tokens)

        end_time = time.time()
        time_taken = end_time - start_time

        # Save tokens JSON after every batch
        save_tokens_to_json(all_tokens)

        # Log summary every 1000 requests
        if total_requests % 1000 == 0:
            log_text = (
                f"==== Summary after {total_requests} requests ====\n"
                f"Pass: {pass_count}\n"
                f"Fail: {fail_count}\n"
                f"Time for last batch: {time_taken:.2f} seconds\n"
                f"----------------------------------------"
            )
            print(log_text)
            append_log_to_txt(log_text)

if __name__ == "__main__":
    run_test()
