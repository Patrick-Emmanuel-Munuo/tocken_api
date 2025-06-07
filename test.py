import requests
import random
import time
from datetime import datetime

API_URL = "http://127.0.0.1:1010/decrypt_token"
LOG_FILE = "token_test_log.txt"
SUMMARY_EVERY = 50  # print summary every N requests
DELAY_SECONDS = 0.1  # delay between requests


def generate_random_20_digit_token():
    return ''.join(str(random.randint(0, 9)) for _ in range(20))


def log_result(log_file, token, status_code, response_text, elapsed_ms):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_file.write(f"[{timestamp}] Token: {token} | Status: {status_code} | Time: {elapsed_ms:.2f} ms\n")
    log_file.write(f"Response: {response_text}\n")
    log_file.write("-" * 80 + "\n")
    log_file.flush()


def test_api_call(token):
    params = {"token": token}
    start = time.perf_counter()
    try:
        response = requests.get(API_URL, params=params)
        elapsed_ms = (time.perf_counter() - start) * 1000
        return response.status_code, response.text, elapsed_ms
    except Exception as e:
        elapsed_ms = (time.perf_counter() - start) * 1000
        return None, str(e), elapsed_ms


def run_infinite_test():
    total_tests = 0
    total_time = 0
    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"\n{'='*20} Test started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {'='*20}\n\n")
        print("Starting infinite token testing... Press Ctrl+C to stop.")
        try:
            while True:
                token = generate_random_20_digit_token()
                status_code, response_text, elapsed_ms = test_api_call(token)
                log_result(log_file, token, status_code, response_text, elapsed_ms)

                total_tests += 1
                total_time += elapsed_ms

                if total_tests % SUMMARY_EVERY == 0:
                    avg_time = total_time / total_tests
                    summary = f"[{datetime.now().strftime('%H:%M:%S')}] Tests run: {total_tests}, Avg response time: {avg_time:.2f} ms"
                    print(summary)
                    log_file.write(summary + "\n" + ("=" * 80) + "\n")
                    log_file.flush()

                time.sleep(DELAY_SECONDS)
        except KeyboardInterrupt:
            avg_time = total_time / total_tests if total_tests else 0
            print("\nTest interrupted by user.")
            final_summary = (
                f"Total tests run: {total_tests}\n"
                f"Average response time: {avg_time:.2f} ms\n"
                f"Test ended at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                + "=" * 80
            )
            print(final_summary)
            log_file.write("\n" + final_summary + "\n")
            log_file.flush()


if __name__ == "__main__":
    run_infinite_test()
