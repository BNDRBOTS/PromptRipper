**README.md**
```markdown
# Prompt Ripper Pro

Production-grade prompt extraction and analysis tool with a web interface. Supports fuzzy matching for speech-to-text errors, multiple file formats, red-team risk detection, and semantic search.

## Features

- Upload: TXT, MD, JSON, CSV, LOG, PDF, DOCX, PNG, JPG, JPEG, TIFF, BMP
- OCR via Tesseract for images
- Fuzzy prompt matching (handles STT misrecognitions like "prop", "crop", etc.)
- Multi-key JSON extraction (`prompt`, `say`, `user`, `agent`, etc.)
- Deduplication with configurable similarity threshold
- Red-team risk scoring and flags
- Utility scoring
- Semantic search (SentenceTransformers + FAISS)
- Lexical search (TF-IDF)
- Real-time progress via Server-Sent Events
- Dark/light mode toggle
- Mobile-responsive design

## Requirements

- Python 3.9+
- Tesseract OCR installed on the system
  - Ubuntu/Debian: `sudo apt install tesseract-ocr`
  - macOS: `brew install tesseract`
  - Windows: Download from https://github.com/UB-Mannheim/tesseract/wiki

## Installation

1. Clone the repository.
2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Ensure Tesseract is in your PATH.

## Running Locally

```bash
python app.py
```

Open http://localhost:5000 in your browser.

## Deploying to Railway

1. Push this repository to GitHub.
2. Create a new project on Railway and connect the repository.
3. Railway will automatically use the `railway.json` configuration.
4. Set the `PORT` environment variable (Railway provides it automatically).
5. The healthcheck endpoint `/health` verifies upload folder, Tesseract, and `ripper.py` availability.

## API Endpoints

- `POST /upload` – Upload file with options (`similarity`, `min_utility`, `keep_duplicates`). Returns `job_id`.
- `GET /stream/{job_id}` – SSE stream for progress updates.
- `GET /results/{job_id}` – Get final JSON results.
- `GET /search?q=...&method=semantic|lexical|both&top_k=10` – Search extracted prompts.
- `POST /build_index` – (Internal) Rebuild search index.
- `GET /health` – Health check with real dependency verification.

## Configuration

All options are available via the UI. The underlying `ripper.py` script can also be run standalone:

```bash
python ripper.py input.txt output.json [--similarity 0.92] [--min-utility 0] [--keep-duplicates]
```

## Data Flow

1. File uploaded.
2. Text extracted based on file type (PDF, DOCX, image OCR, plain text).
3. Text saved as temporary `.txt`.
4. `ripper.py` subprocess extracts prompts, scores risk/utility, deduplicates.
5. Results saved as JSON.
6. Search indices built in-memory.
7. Frontend displays results and allows search.

## Security Notes

- Uploaded files are stored in a temporary directory and never persisted beyond the session.
- The `ripper.py` script runs as a subprocess with the same user permissions; ensure your deployment environment restricts file system access appropriately.
- No external API calls are made; all processing is local.

## License

MIT
```
