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
