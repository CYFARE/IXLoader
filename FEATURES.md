| Feature | Description |
|---------|-------------|
| **Input Flexibility** | Process single files or entire folders (`-i`/`--input`). Supports PNG, JPG/JPEG, GIF, BMP, TIFF, WebP, AVIF/HEIC, ICO, SVG, JP2 |
| **Smart Multiprocessing** | Auto-selects Thread vs Process executor based on workload. Manual override with `--executor {thread,process}`. Process mode is fully picklable — workers construct their own logger and payload processor from a `WorkerConfig` |
| **Binary Payload Support** | Multiple payload formats: `text` (default), `hex`, `base64`, `file` via `--payload-format`. With `--payload-format file`, all payload paths are validated up front — missing files are reported before any injection work begins |
| **Payload Templating** | Dynamic placeholders: `{{FILE}}`, `{{RAND:n}}`, `{{DIMS}}`, `{{UUID}}`, `{{TIMESTAMP}}` |
| **Selective Mutations** | Choose injection points: `header`, `body`, `trailer`, `exif`, `xmp`, `text_chunk`, `icc` via `--mutations`. Values are enum-validated — unknown values fail fast (exit 2) with a usage line listing valid options |
| **Advanced Injection** | Format-aware injection with proper chunk structures (PNG IHDR/tEXt/iCCP, JPEG COM/APPn/EXIF, GIF Comment Extensions). GIF body injection parses the Logical Screen Descriptor and skips the Global Color Table, so the comment extension never lands inside palette bytes. JPEG SOS segment length is bounds-checked to prevent misreads on truncated files |
| **Configurable PNG tEXt Keyword** | `--png-text-keyword` sets the keyword used by PNG text-chunk injection (default `Comment`). Validated per PNG spec: 1–79 Latin-1 bytes, no null bytes, no leading/trailing whitespace |
| **Valid CRC Generation** | Proper CRC32 calculation for PNG chunks (no more placeholder CRCs) |
| **DoS Image Generation** | Create stress-test images: `pixel_flood`, `long_body`, `decompression_bomb`, `iccp_dos` via `--dos-types`. `--dos-types` values are enum-validated the same way as `--mutations` |
| **Safety Controls** | `--force` required for non-empty output dirs, memory checks before large allocations, `--i-understand` for DoS mode. `Image.MAX_IMAGE_PIXELS` override is scoped to the operations that need it rather than set globally |
| **Per-Task Timeout (Linux)** | `--task-timeout N` aborts a hung mutation (or DoS creation) after N seconds via SIGALRM. Default 300, `0` disables. Only enforced with `--executor process` (SIGALRM requires the main thread); thread-based executors log a warning and skip the timer. Native Pillow decode paths may not honor SIGALRM — documented limitation |
| **Working Dry-Run** | `--dry-run` prints the full list of planned `(input, payload_idx, mutation, output_path)` tuples and exits without writing anything |
| **Resumable Operations** | `--resume` skips existing files, allowing interrupted runs to continue |
| **Flexible File Discovery** | `--pattern` for glob filtering, `--recursive` for directory traversal |
| **Machine-Readable Output** | Generate `manifest.json` or `manifest.csv` with SHA256, size, status, parse validation |
| **Structured Logging** | `-v`/`--verbose` for INFO, `-vv` for DEBUG, `--log-file` for persistent logs. `psutil` is imported lazily — memory checks are skipped with a single info line when the dependency is absent |
| **Reproducibility** | `--seed N` seeds Python's `random` *and* monkey-patches `uuid.uuid4` so output SHA256s are byte-identical across runs with the same seed and worker count. A warning is emitted because deterministic UUIDs are no longer cryptographically random |
| **Validation** | `--validate` runs `Image.verify()` (fast container check). `--validate-deep` also forces a full pixel decode via `Image.load()` — catches bugs that shallow verify misses, at the cost of decode time. `--validate-deep` implies `--validate` |
| **Per-Format Statistics** | Success/failure breakdown by image format and injection type in summary |
| **Collision-Resistant Names** | Hash-based filename generation prevents `a.b.png` vs `a_b.png` collisions. Filename computation happens up front in the main process so the dedup set is populated, and repeat inputs get unique outputs |
