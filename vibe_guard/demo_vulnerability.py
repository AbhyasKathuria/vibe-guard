# test_code.py
import subprocess

# Vulnerability 1: Hardcoded API key
API_KEY = "AIzaSyD-TEST-KEY-1234567890abcdef"


# Vulnerability 2: Subprocess call with shell=True
def run_command(user_input):
    # This is a classic security-audit finding
    subprocess.run(f"echo {user_input}", shell=True)
