# JSBOSS

**JSBOSS** is a Python-based tool for extracting JavaScript links and secrets from JavaScript files. This tool allows you to easily scan multiple URLs or files for sensitive information such as API keys, secret tokens, and more.

## Features

- Extract URLs from JavaScript files
- Identify and extract sensitive secrets, like AWS keys, Stripe tokens, GitHub tokens, and many more
- Auto-generate an output file with a unique name based on the given domain
- Supports input through both single URLs or a file containing multiple URLs

## Usage

### Prerequisites

1. Python 3.x
2. Install required dependencies:

    ```bash
    pip install -r requirements.txt
    ```

### Command-line Arguments

JSBOSS supports the following command-line arguments:

- `-f, --file`: Specify a file containing a list of JavaScript URLs.
- `-o, --output_file`: Specify the output file to save extracted links. Defaults to `extracted_links.txt`.
- `-u, --url`: Check a single JavaScript URL.
- `--secrets`: Look for sensitive secrets within JavaScript content.
- `--urls`: Extract all URLs within the JavaScript content.

### Running the Tool

To scan a single URL for secrets and links:

```bash
python jsboss.py -u https://example.com/somefile.js --secrets --urls

### To scan multiple JavaScript URLs from a file:

python jsboss.py -f urls.txt --secrets --urls
```

### Result

```bash
python jsboss.py -f js_links.txt --secrets
```

This command will read all URLs from `js_links.txt`, extract any secrets, and save the results in an 
output file named `output_<domain>.txt`.

## Auto-generated Output Files

When scanning multiple files, JSBOSS automatically generates output files named in the format: 
`output_<domain>.txt`. For instance, if a JavaScript file is hosted on `example.com`, the output will 
be saved in `output_example.com.txt`.
