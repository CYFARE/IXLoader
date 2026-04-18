<h1 align="center">
  <img src="https://github.com/CYFARE/IXLoader/blob/main/assets/IXLoader.png" alt="IXLoader Logo">
</h1>

<h2 align="center">
  <img src="https://img.shields.io/badge/-GPLv2.0-61DAFB?style=for-the-badge" alt="License: GPLv2.0">&nbsp;
</h2>

**IXLoader**, or **I**mage e**X**ploit **L**oader - A tool designed to generate large sets of image payloads for security research.

## Releases & Features

### Release Cycle

This is a rolling release tool, which means that new features will not follow any release cycles and will constantly be added anytime. So always make sure you `git clone` the project periodically! The feature list below will be updated as the features are added, so you can refer to the new feature sets easily.

### Features

<h1 align="center">
  <img src="https://github.com/CYFARE/IXLoader/blob/main/assets/features.png" alt="IXLoader Features">
</h1>

Complete Features List: https://github.com/CYFARE/IXLoader/blob/main/FEATURES.md

Sample Payloaded Image:

<h1 align="center">
  <img src="https://github.com/CYFARE/IXLoader/blob/main/assets/sample_hex_01.png" alt="Sample Payloaded Image">
</h1>

## Setup & Usage

### Setup

```bash
cd ~ && git clone https://github.com/CYFARE/IXLoader.git 
cd IXLoader
python3 -m venv venv # Or use 'python' depending on your system
source venv/bin/activate # On Windows use `venv\Scripts\activate`
# Install dependencies
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### Usage

#### 1. Inject Payloads (Basic)

```bash
# Inject payloads into a single image
python load.py inject -i clean.png -p sample_xss.txt

# Inject into all images in a folder with recursive scan
python load.py inject -i input_images/ -p payloads.txt --recursive
```

#### 2. Advanced Injection Options

```bash
# Select specific mutations only (header and trailer)
python load.py inject -i images/ -p payloads.txt --mutations header,trailer

# Use hex-encoded binary payloads
python load.py inject -i clean.png -p binary.hex --payload-format hex

# Load payloads from files (each payload is a file path; all paths are validated up front)
python load.py inject -i clean.png -p file_list.txt --payload-format file

# Add EXIF and XMP injection for JPEGs with validation
python load.py inject -i photos/ -p payloads.txt --mutations header,exif,xmp --validate

# Deep validation: verify() plus full pixel decode (catches more bugs, slower)
python load.py inject -i photos/ -p payloads.txt --validate-deep

# Customize the PNG tEXt keyword (1-79 Latin-1 bytes, default "Comment")
python load.py inject -i images/ -p payloads.txt --mutations text_chunk --png-text-keyword Description

# Dry run to preview what would be generated (no files written)
python load.py inject -i images/ -p payloads.txt --dry-run

# Per-task timeout via SIGALRM (requires --executor process on Linux)
python load.py inject -i images/ -p payloads.txt --executor process --task-timeout 60

# Resume interrupted run (skip existing files)
python load.py inject -i images/ -p payloads.txt --resume

# Custom pattern and output with logging
python load.py inject -i input/ -p payloads.txt --pattern "*.png" -o output/ --log-file run.log -v
```

#### 3. Generate DoS Images

```bash
# Generate all DoS types (requires acknowledgment)
python load.py dos --i-understand -o dos_output/

# Generate specific DoS types only
python load.py dos --i-understand --dos-types pixel_flood,decompression_bomb -o dos/

# Resume partial DoS generation
python load.py dos --i-understand --dos-types long_body --resume -o dos/
```

#### 4. Process & Report

```bash
# Generate JSON manifest with SHA256 hashes
python load.py inject -i images/ -p payloads.txt --manifest --manifest-format json

# Generate CSV report for spreadsheet analysis
python load.py inject -i images/ -p payloads.txt --manifest --manifest-format csv

# Full verbose with validation and manifest
python load.py inject -i images/ -p payloads.txt -vv --validate --manifest --log-file debug.log
```

#### 5. Reproducible & Safe Operations

```bash
# Deterministic run with seed (same output order every time)
python load.py inject -i images/ -p payloads.txt --seed 42

# Force overwrite existing output directory (DANGEROUS - use carefully)
python load.py inject -i images/ -p payloads.txt --force

# Process with memory safety checks (auto-enabled for DoS)
python load.py inject -i large_images/ -p payloads.txt --executor process
```

**Important Safety Notes:**
- Output directory is protected: requires `--force` to overwrite non-empty directories
- DoS mode requires `--i-understand` flag to acknowledge risks
- Use `--resume` to continue interrupted runs without regenerating existing files
- Memory checks prevent OOM when generating large DoS images

## Support

Boost Cyfare by spreading a word and considering your support: https://cyfare.net/apps/Social/ 

## License

GPLv2.0
