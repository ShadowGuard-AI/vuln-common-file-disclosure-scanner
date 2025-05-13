import argparse
import logging
import requests
import os
import sys
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define common sensitive files to check
COMMON_FILES = [
    ".env",
    "docker-compose.yml",
    "config.php",
    "wp-config.php",
    ".git/config",
    "application.yml",
    "application.properties",
    "database.yml",
    "web.config",
    "config.ini",
    "secrets.yml"
]

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description="Scans for the presence of publicly accessible files that commonly contain sensitive information.")
    parser.add_argument("url", help="The URL of the website to scan.")
    parser.add_argument("-f", "--files", nargs="+", help="List of files to scan (overrides default list).", default=COMMON_FILES)
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Timeout for HTTP requests (default: 5 seconds).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (debug logging).")
    parser.add_argument("-o", "--output", help="Output file to save results to.")
    return parser

def check_file_exists(url, filename, timeout=5):
    """
    Checks if a file exists at the given URL.

    Args:
        url (str): The base URL of the website.
        filename (str): The name of the file to check.
        timeout (int): Timeout for the HTTP request in seconds.

    Returns:
        bool: True if the file exists and returns a 200 status code, False otherwise.
    """
    try:
        target_url = urljoin(url, filename)  # Construct the full URL
        logging.debug(f"Checking for: {target_url}")
        response = requests.get(target_url, timeout=timeout, allow_redirects=True)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        if response.status_code == 200:
            logging.info(f"Found: {target_url} (Status Code: {response.status_code})")
            return True, target_url, response.text # return the url and the content
        else:
            logging.debug(f"Not Found: {target_url} (Status Code: {response.status_code})")
            return False, target_url, None

    except requests.exceptions.RequestException as e:
        logging.debug(f"Error checking {filename}: {e}")
        return False, target_url, None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return False, target_url, None


def urljoin(base, url):
    """
    Joins a base URL with a relative URL, handling trailing slashes.

    Args:
        base (str): The base URL.
        url (str): The relative URL to join.

    Returns:
        str: The combined URL.
    """
    if base.endswith('/'):
        base = base[:-1]  # Remove trailing slash from base URL if present
    if url.startswith('/'):
        url = url[1:]  # Remove leading slash from URL if present
    return f"{base}/{url}"

def validate_url(url):
    """
    Validates that the provided URL is properly formatted.

    Args:
        url (str): The URL to validate.

    Returns:
        bool: True if the URL is valid, False otherwise.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False


def main():
    """
    Main function to execute the vulnerability scanner.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not validate_url(args.url):
        logging.error("Invalid URL provided.  Please provide a full URL (e.g., http://example.com)")
        sys.exit(1)

    logging.info(f"Starting scan for {args.url}...")

    found_files = {}  # Store found files and their content

    for filename in args.files:
        exists, url, content = check_file_exists(args.url, filename, args.timeout)
        if exists:
            found_files[url] = content

    if found_files:
        logging.info("The following potentially sensitive files were found:")
        for url, content in found_files.items():
            logging.info(f"- {url}")
    else:
        logging.info("No sensitive files were found.")
        
    if args.output:
      try:
        with open(args.output, "w") as f:
            if found_files:
                f.write("Potentially sensitive files found:\n")
                for url, content in found_files.items():
                    f.write(f"URL: {url}\n")
                    f.write(f"Content:\n{content}\n")
                    f.write("-" * 40 + "\n")
            else:
                f.write("No sensitive files found.\n")
        logging.info(f"Results saved to {args.output}")

      except Exception as e:
        logging.error(f"Error writing to output file: {e}")


if __name__ == "__main__":
    main()