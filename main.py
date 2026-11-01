import argparse
import logging
import requests
import os
import sys
import hashlib
from urllib.parse import urlparse

# A name that will not exist on a real target. Its response is the baseline:
# a probe that answers exactly like this absent file is a catchall page,
# not a disclosed file.
BASELINE_FILE = "baseline-absent-9f3k7q.txt" 

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
    parser.add_argument("--include-content", action="store_true", help="Include full file contents in the output file. By default the report records URL, status, size, and a SHA-256 hash only.")
    return parser

def fetch_file(url, filename, timeout=5):
    """
    Fetches one path and reports what actually happened.

    Returns:
        tuple: (target_url, response_or_None, error_or_None). A response of
        any status means the target was reached; an error means it was not.
    """
    target_url = urljoin(url, filename)
    logging.debug(f"Checking for: {target_url}")
    try:
        response = requests.get(target_url, timeout=timeout, allow_redirects=True)
        return target_url, response, None
    except requests.exceptions.RequestException as e:
        logging.debug(f"Error checking {filename}: {e}")
        return target_url, None, e
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return target_url, None, e


def body_hash(text):
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


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

    # Baseline first: fetch a file that is certainly absent, so a catchall
    # server that answers 200 for every path cannot manufacture findings.
    _, baseline_response, baseline_error = fetch_file(args.url, BASELINE_FILE, args.timeout)
    baseline_status = baseline_response.status_code if baseline_response is not None else None
    baseline_hash = body_hash(baseline_response.text) if baseline_response is not None else None

    found_files = {}  # url -> report dict (content only with --include-content)
    reached = 0
    attempted = 0

    for filename in args.files:
        attempted += 1
        url, response, error = fetch_file(args.url, filename, args.timeout)
        if response is None:
            continue
        reached += 1
        if response.status_code != 200:
            logging.debug(f"Not Found: {url} (Status Code: {response.status_code})")
            continue
        digest = body_hash(response.text)
        if baseline_status == 200 and digest == baseline_hash:
            logging.debug(f"Matches the baseline response, not a finding: {url}")
            continue
        logging.info(f"Found: {url} (Status Code: {response.status_code})")
        entry = {
            "status": response.status_code,
            "size": len(response.content),
            "sha256": digest,
        }
        if args.include_content:
            entry["content"] = response.text
        found_files[url] = entry

    if attempted and reached == 0:
        logging.error("Scan did not complete: no probe reached the target. No verdict is reported.")
        sys.exit(1)

    if found_files:
        logging.info("The following potentially sensitive files were found:")
        for url in found_files:
            logging.info(f"- {url}")
    else:
        logging.info("No sensitive files were found.")

    if args.output:
      try:
        with open(args.output, "w") as f:
            if found_files:
                f.write("Potentially sensitive files found:\n")
                for url, entry in found_files.items():
                    f.write(f"URL: {url}\n")
                    f.write(f"Status: {entry['status']}\n")
                    f.write(f"Size: {entry['size']}\n")
                    f.write(f"SHA-256: {entry['sha256']}\n")
                    if "content" in entry:
                        f.write(f"Content:\n{entry['content']}\n")
                    f.write("-" * 40 + "\n")
            else:
                f.write("No sensitive files found.\n")
        logging.info(f"Results saved to {args.output}")

      except Exception as e:
        logging.error(f"Error writing to output file: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()