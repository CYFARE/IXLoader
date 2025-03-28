<h1 align="center">
  <img src="https://github.com/CYFARE/IXLoader/blob/main/assets/IXLoader.png" alt="IXLoader Logo">
</h1>

<h2 align="center">
  <img src="https://img.shields.io/badge/-MPLv2.0-61DAFB?style=for-the-badge" alt="License: GPLv2.0">&nbsp;
</h2>

**IXLoader**, or **I**mage e**X**ploit **L**oader - A tool designed to generate large sets of image payloads for security research.

## Releases & Features

### Release Cycle

This is a rolling release tool, which means that new features will not follow any release cycles and will constantly be added anytime. So always make sure you git clone the project periodically! The feature list below will be updated as the features are added, so you can reffer the new feature sets easily.

### Features

```
- Inject Mode
  - Injects Payload Into Header
  - Injects Payload Into Body
  - Injects Payload Into Trailer
- DoS Generator
  - Pixel Flood Image
  - Long Body Image
  - Decompression Bomb
  - Color Profile DoS
```

Features In-Development:

- Create from multiple input images

## Setup & Usage

### Setup

```bash
cd ~ && git clone https://github.com/CYFARE/IXLoader.git
cd IXLoader
python -m venv venv
source venv/bin/activate
python -m pip install -r requirements.txt
```

### Usage

- Get any type of payload set in a file (provided example: sample_xss.txt)
- Get some clean image (provided example: clean.png)
- Run:

```bash
python load.py -i clean.png -p sample_xss.txt
```

- You will see folder created called 'loaded' will all new image payloads. Please rename the folder to anything else so that you don't loose the set of payloads on next run!
- For generating DoS images using clean.png, run:

```bash
python load.py -i clean.png --dosimage
```

- You will see folder called 'loaded' with 4 DoS images created using clean.png

## Support

Boost Cyfare by spreading a word and considering your support: https://cyfare.net/apps/Social/

## License

GPLv2.0
