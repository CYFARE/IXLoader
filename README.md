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

* **Input Flexibility**: Process a single image file or an entire folder containing multiple images (`-i`/`--input`). Supports common image formats (PNG, JPG/JPEG, GIF, etc.).
* **Automatic Multiprocessing**: Intelligently utilizes multiple CPU cores for significantly faster processing of large image sets or payload lists (no manual thread count needed).
* **Configurable Output**: Specify a custom output directory for generated images (`-o`/`--output`, defaults to `loaded`). The directory is cleared before each run.
* **Verbose Output**: Control the level of detail printed during execution using `-v` or `-vv`.
* **Payload Injection Mode**:
    * Injects each payload from a specified file (`-p`/`--payloads`) into input image(s).
    * Creates 3 variants for each image-payload combination by injecting into:
        * Image Header
        * Image Body (near middle or specific markers)
        * Image Trailer (appended)
* **DoS Image Generation Mode** (`--dosimage`):
    * Generates various types of potentially Denial-of-Service-inducing images.
    * Ignores payload file (`-p`).
    * Current DoS types include:
        * Pixel Flood (Large dimension PNG)
        * Long Body (PNG with large metadata)
        * Long Body (JPG with large comment segment)
        * Decompression Bomb (PNG declaring large dimensions)
        * Color Profile DoS (PNG with large declared iCCP chunk)

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

#### 1. Inject Payloads into a Single Image

```bash
# Inject payloads from sample_xss.txt into clean.png
# Output goes to the default 'loaded/' directory
# Uses automatic multithreading based on your CPU cores
python load.py -i clean.png -p sample_xss.txt
```

#### 2. Inject Payloads into All Images in a Folder

```bash
# Create a folder (e.g., 'input_images') and place clean images inside
# Inject payloads into all supported images found in 'input_images/'
# Save results to a custom directory 'payloaded_output/'
python load.py -i input_images -p sample_xss.txt
```

#### 3. Generate DoS Images

```bash
# Generate various DoS image types.
# The input image (-i) is required by the script but may be ignored by specific DoS generators.
# Payloads (-p) are ignored in this mode.
# Output goes to the 'dos_output/' directory
python load.py -i clean.png --dosimage -o dos_output
```

**Important:** The output directory (default loaded/ or specified with -o) is cleared before each run. If you want to keep the generated images, rename or move the output folder after the script finishes!

## Support

Boost Cyfare by spreading a word and considering your support: https://cyfare.net/apps/Social/

## License

GPLv2.0
