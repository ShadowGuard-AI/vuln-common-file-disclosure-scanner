# vuln-Common-File-Disclosure-Scanner

I wrote this to check one named site for files that should never be public: .env, wp-config.php, secrets.yml, and the rest of the usual list. It probes each name, and before it believes any of them it fetches a baseline file name that cannot exist, so a catchall server that answers 200 for every path does not turn into eleven fake findings. A file counts as found only when its answer differs from that baseline.

The report is deliberately thin. By default the output file records the URL, the status, the size, and a SHA-256 hash of what came back, not the contents, because the files on this list hold credentials by design and a report should not become a second copy of them. Pass `--include-content` only when you really need the full contents captured.

If no probe reaches the target at all, the run exits non-zero and reports no verdict, instead of calling an unreachable site clean.

## Install
`git clone https://github.com/ShadowGuard-AI/vuln-common-file-disclosure-scanner`

## Usage
`python main.py <url> [params]`

Example: `python main.py http://127.0.0.1:8080 -o report.txt`

## Parameters
- `-h`: Show help message and exit
- `-f`: List of files to scan (overrides the default list).
- `-t`: Timeout for HTTP requests in seconds (default: 5).
- `-v`: Enable verbose output.
- `-o`: Output file to save results to.
- `--include-content`: Include full file contents in the output file. Off by default.

## License
Copyright (c) ShadowGuard-AI
