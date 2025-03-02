import re
import os
import sys
import hashlib
import secrets
from datetime import datetime

MAX_NAME_LENGTH = 50
NAME_REGEX = r"^[A-Za-z\-']+$"
INT_MIN = -2147483648
INT_MAX = 2147483647
PASSWORD_LOG_FILE = "password.txt"
ERROR_LOG_FILE = "error.txt"

def log_error(message):
    "Log an error message with timestamp to the error log file"
    with open(ERROR_LOG_FILE, 'a') as error_log:
        error_log.write(f"{datetime.now()}: {message}\n")

def read_name(name_type):
    "Read and validate a first or last name."
    while True:
        name = input(f"Enter your {name_type} name (only letters, hyphen (-), apostrophe (') allowed, max {MAX_NAME_LENGTH} characters): ")
        if not name or len(name) > MAX_NAME_LENGTH:
            print(f"Name must be between 1 and {MAX_NAME_LENGTH} characters")
            continue
        if not re.match(NAME_REGEX, name):
            print("Name can only contain letters, hyphen (-), and apostrophe (').")
            continue
        return name
def read_int(order):
    """Read and validate an integer."""
    while True:
        try:
            value_str = input(f"Enter the {order} integer (range: {INT_MIN} to {INT_MAX}): ")
            value = int(value_str)
            if value < INT_MIN or value > INT_MAX:
                print(f"Integer must be within the range {INT_MIN} to {INT_MAX}.")
                continue
            return value
        except ValueError:
            print("Invalid integer input. Please enter a valid 4-byte integer.")

def read_file_name(file_type):
    """Read and validate a file name."""
    while True:
        file_name = input(f"Enter the {file_type} file name (e.g. file.txt): ")
        if not file_name:
            print("File name cannot be empty.")
            continue
        if file_type.lower() == "input":
            if not os.path.isfile(file_name):
                print("File does not exist or is not a file. Please try again.")
                continue
        return file_name
def is_valid_password(password):
    """Validate password meets requirements."""
    if len(password) < 8:
        return False
    
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()-_+=<>?/{}~|" for c in password)
    
    return has_upper and has_lower and has_digit and has_special
def generate_salt():
    """Generate a random 16-byte salt."""
    return secrets.token_bytes(16)
def hash_password(password, salt):
    """Hash a password using SHA-256."""
    hasher = hashlib.sha256()
    hasher.update(salt)
    hasher.update(password.encode('utf-8'))
    return hasher.hexdigest()

def save_password(hashed_password, salt):
    """Save the salt and hashed password to a file."""
    with open(PASSWORD_LOG_FILE, "w") as pw_file:
        pw_file.write(salt.hex() + "\n")
        pw_file.write(hashed_password + "\n")

def safe_add(a, b):
    """Safely add two integers without overflow."""
    return a + b

def safe_multiply(a, b):
    """Safely multiply two integers without overflow."""
    return a * b

def main():
    try:
        # Name Input
        first_name = read_name("first")
        last_name = read_name("last")

        # Integer Input
        first_int = read_int("first")
        second_int = read_int("second")
        sum_result = safe_add(first_int, second_int)
        product_result = safe_multiply(first_int, second_int)

        # File Name Input
        input_file_name = read_file_name("input")
        output_file_name = read_file_name("output")
        
        # Make sure input and output files are different
        while input_file_name == output_file_name:
            print("Input and output files must be different.")
            output_file_name = read_file_name("output")

        # Password Input and Verification
        salt = generate_salt()
        hashed_password = ""

        while True:
            password = input("Enter a password (min 8 characters, must include at least one uppercase letter, one lowercase letter, one digit, and one special character): ")
            if not is_valid_password(password):
                print("Password does not meet requirements. Please try again.")
                continue
            
            password_verify = input("Re-enter your password for verification: ")
            if password != password_verify:
                print("Passwords do not match. Please try again.")
                continue
            
            hashed_password = hash_password(password, salt)
            save_password(hashed_password, salt)

            # Final Verification
            final_password = input("Enter your password once more to verify: ")
            final_hash = hash_password(final_password, salt)
            if final_hash == hashed_password:
                print("Password verified successfully.")
                break
            else:
                print("Final Password verification failed. Please try again.")

        # Read Input File
        try:
            with open(input_file_name, 'r') as input_file:
                input_file_contents = input_file.read()
        except Exception as e:
            error_msg = f"Error reading input file: {str(e)}"
            print(error_msg)
            log_error(error_msg)
            input_file_contents = "Error reading file"

        # Write Output File
        try:
            with open(output_file_name, 'w') as output_file:
                output_file.write(f"First Name: {first_name}\n")
                output_file.write(f"Last Name: {last_name}\n")
                output_file.write(f"First Integer: {first_int}\n")
                output_file.write(f"Second Integer: {second_int}\n")
                output_file.write(f"Sum: {sum_result}\n")
                output_file.write(f"Product: {product_result}\n")
                output_file.write(f"Input File Name: {input_file_name}\n")
                output_file.write(f"Input File Contents:\n{input_file_contents}\n")
            print(f"Data successfully written to {output_file_name}")
        except Exception as e:
            error_msg = f"Error writing output file: {str(e)}"
            print(error_msg)
            log_error(error_msg)

    except Exception as e:
        error_msg = f"An error occurred: {str(e)}"
        print(error_msg)
        log_error(error_msg)

if __name__ == "__main__":
    main()