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

| Feature | Description |
|---------|-------------|
| **Input Flexibility** | Process single files or entire folders (`-i`/`--input`). Supports PNG, JPG/JPEG, GIF, BMP, TIFF, WebP, AVIF/HEIC, ICO, SVG, JP2 |
| **Smart Multiprocessing** | Auto-selects Thread vs Process executor based on workload. Manual override with `--executor {thread,process}` |
| **Binary Payload Support** | Multiple payload formats: `text` (default), `hex`, `base64`, `file` via `--payload-format` |
| **Payload Templating** | Dynamic placeholders: `{{FILE}}`, `{{RAND:n}}`, `{{DIMS}}`, `{{UUID}}`, `{{TIMESTAMP}}` |
| **Selective Mutations** | Choose injection points: `header`, `body`, `trailer`, `exif`, `xmp`, `text_chunk`, `icc` via `--mutations` |
| **Advanced Injection** | Format-aware injection with proper chunk structures (PNG IHDR/tEXt/iCCP, JPEG COM/APPn/EXIF, GIF Comment Extensions) |
| **Valid CRC Generation** | Proper CRC32 calculation for PNG chunks (no more placeholder CRCs) |
| **DoS Image Generation** | Create stress-test images: `pixel_flood`, `long_body`, `decompression_bomb`, `iccp_dos` via `--dos-types` |
| **Safety Controls** | `--force` required for non-empty output dirs, memory checks before large allocations, `--i-understand` for DoS mode |
| **Resumable Operations** | `--resume` skips existing files, allowing interrupted runs to continue |
| **Flexible File Discovery** | `--pattern` for glob filtering, `--recursive` for directory traversal |
| **Machine-Readable Output** | Generate `manifest.json` or `manifest.csv` with SHA256, size, status, parse validation |
| **Structured Logging** | `-v`/`--verbose` for INFO, `-vv` for DEBUG, `--log-file` for persistent logs |
| **Reproducibility** | `--seed` for deterministic random generation and ordering |
| **Validation** | Optional post-injection validation with Pillow (`--validate`) |
| **Per-Format Statistics** | Success/failure breakdown by image format and injection type in summary |
| **Collision-Resistant Names** | Hash-based filename generation prevents `a.b.png` vs `a_b.png` collisions |

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

# Load payloads from files (each payload is a file path)
python load.py inject -i clean.png -p file_list.txt --payload-format file

# Add EXIF and XMP injection for JPEGs with validation
python load.py inject -i photos/ -p payloads.txt --mutations header,exif,xmp --validate

# Dry run to preview what would be generated
python load.py inject -i images/ -p payloads.txt --dry-run

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
