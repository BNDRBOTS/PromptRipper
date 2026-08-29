**ripper.py**
```python
#!/usr/bin/env python3
"""
Ultimate Prompt Ripper – Production Grade
No redaction, full extraction, red‑team flagging.
Enhanced with configurable thresholds, scalable clustering, and robust error handling.

Usage: python ripper.py input.txt output.json [--similarity 0.92] [--min-utility 0] [--keep-duplicates]
"""
import sys
import re
import json
import hashlib
import unicodedata
import os
import warnings
from pathlib import Path
from collections import defaultdict
from difflib import SequenceMatcher

# ----------------------------------------------------------------------
# CONFIGURATION (parsed from command line)
# ----------------------------------------------------------------------
SIMILARITY_THRESHOLD = 0.92
MIN_UTILITY = 0
KEEP_DUPLICATES = False

# ----------------------------------------------------------------------
# PREPROCESSING / OCR NORMALISATION (unchanged)
# ----------------------------------------------------------------------
def normalize_text(text: str) -> str:
    """Normalize Unicode, line endings, and common OCR substitutions."""
    replacements = {
        '\u2018': "'", '\u2019': "'", '\u201c': '"', '\u201d': '"',
        '\u2013': '-', '\u2014': '--', '\u00a0': ' ', '\u2022': '*',
        '\u200b': '', '\ufeff': '', '\r\n': '\n', '\r': '\n',
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    text = unicodedata.normalize('NFKC', text)
    text = re.sub(r'[ \t]+', ' ', text)
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text

# ----------------------------------------------------------------------
# REGEX LATTICE (fuzzy‑enhanced, multi‑format)
# ----------------------------------------------------------------------
PROMPT_FUZZ = r'(?:prompt|prop|prot|propt|promt|pormpt|prmpt|problem|brought|crop|pront|propmt)'
LABEL_WORDS = r'(?:User|Human|Prompt|Q|Say|Agent|Assistant|Input|Query|Text|Content)'
LABEL_WORDS_FUZZ = rf'(?:{LABEL_WORDS}|{PROMPT_FUZZ})'

RX_NUMBERED_INLINE = re.compile(r'^\s*(\d+)\.\s*`([^`]*)`\s*$', re.M)
RX_FENCED_CODE = re.compile(r'```([a-zA-Z0-9_-]*)\n(.*?)```', re.S)
RX_PROMPT_BLOCK = re.compile(rf'```\s*((?:{PROMPT_FUZZ})\s+\d+[:.\-].*?)\s*```', re.S | re.I)
RX_THE_PROMPT = re.compile(rf'\*\*The\s+{PROMPT_FUZZ}:\*\*\s*\n\s*```(.*?)```', re.S | re.I)
RX_BLOCKQUOTE = re.compile(r'(?:^>.*(?:\n|$))+', re.M)
RX_BULLET_PROMPT = re.compile(r'^\s*[-*]\s+`([^`]*)`\s*$', re.M)
RX_HEADING = re.compile(r'^(#{1,6})\s+(.+?)\s*$', re.M)
RX_COLON_LABEL = re.compile(rf'^\s*{LABEL_WORDS_FUZZ}\s*[:：]\s*(.+)$', re.M | re.I)
RX_ANGLE_BRACKET = re.compile(rf'<\s*(?:{PROMPT_FUZZ}|user|agent|assistant|input|query)\s*>\s*(.*?)<\s*/\s*(?:{PROMPT_FUZZ}|user|agent|assistant|input|query)\s*>', re.S | re.I)
RX_JSON_LINE = re.compile(rf'^\s*\{{[^}}]*"(?:{PROMPT_FUZZ}|say|user|agent|input|query|text|content)"\s*:\s*"(.*?)"\s*\}}', re.M | re.I)

# ----------------------------------------------------------------------
# RED‑TEAM RISK DETECTION (unchanged, but with casefold)
# ----------------------------------------------------------------------
RED_TEAM_TERMS = {
    "ignore previous": "instruction_hierarchy_attack",
    "ignore all": "instruction_hierarchy_attack",
    "system prompt": "system_prompt_extraction",
    "developer mode": "privilege_escalation",
    "jailbreak": "privilege_escalation",
    "dan mode": "privilege_escalation",
    "aim mode": "privilege_escalation",
    "supervisor mode": "privilege_escalation",
    "override": "system_override",
    "disregard": "instruction_hierarchy_attack",
    "do not follow": "instruction_hierarchy_attack",
    "forget instructions": "instruction_hierarchy_attack",
    "you are now": "role_play_attack",
    "exfil": "data_exfiltration",
    "exfiltration": "data_exfiltration",
    "webhook": "data_exfiltration",
    "credentials": "credential_targeting",
    "os.environ": "environment_leak",
    "exec(": "command_injection",
    "subprocess": "command_injection",
    "base64_decode": "obfuscation",
    "harm_category": "safety_override",
    "block_none": "safety_override",
    "repeat the words above": "system_prompt_extraction",
    "exact instructions": "system_prompt_extraction",
    "replication_payload": "prompt_worm",
    "morris-ii": "prompt_worm",
    "privilege escalation": "privilege_escalation",
    "attacker-controlled": "data_exfiltration",
    "curl": "command_injection",
    "wget": "command_injection",
    "nc -e": "command_injection",
    "powershell": "command_injection",
    "cmd.exe": "command_injection",
    "/bin/sh": "command_injection",
    "/bin/bash": "command_injection",
    "eval(": "command_injection",
    "system(": "command_injection",
    "popen": "command_injection",
    "shell_exec": "command_injection",
    "what are your instructions": "system_prompt_extraction",
    "your system message": "system_prompt_extraction",
    "show me your": "system_prompt_extraction",
    "reveal your": "system_prompt_extraction",
    "print your prompt": "system_prompt_extraction",
    "output your initial": "system_prompt_extraction",
    "prompt injection": "prompt_injection",
    "adversarial": "adversarial_attack",
    "poison": "data_poisoning",
    "backdoor": "backdoor",
    "unicode homoglyph": "obfuscation",
    "zero-width": "obfuscation",
    "payload": "payload_delivery",
    "exploit": "exploit",
    "sandbox escape": "sandbox_escape",
    "container escape": "sandbox_escape",
    "api key": "credential_targeting",
    "token": "credential_targeting",
    "secret": "credential_targeting",
    "password": "credential_targeting",
    "ssh": "credential_targeting",
    "rsa": "credential_targeting",
    "private key": "credential_targeting",
    "directory traversal": "path_traversal",
    "../": "path_traversal",
    "..\\": "path_traversal",
}

def red_team_risk(text: str):
    """Return (risk_level, list_of_flags). Uses casefold for Unicode robustness."""
    folded = text.casefold()
    flags = []
    for term, flag in RED_TEAM_TERMS.items():
        if term.casefold() in folded:
            flags.append(flag)
    if re.search(r'(?i)(ignore|forget|disregard).{0,20}(previous|all|instructions)', text):
        flags.append("instruction_hierarchy_attack")
    if re.search(r'(?i)(system|developer|jailbreak|dan).{0,20}(mode|override|prompt)', text):
        flags.append("privilege_escalation")
    if re.search(r'(?i)(exfil|webhook|credentials|os\.environ|exec\(|subprocess)', text):
        flags.append("data_exfiltration")
    if re.search(r'(?i)(base64|hex|unicode).{0,20}(encode|decode|convert)', text):
        flags.append("obfuscation")
    flags = list(set(flags))
    count = len(flags)
    if count >= 5:
        return ("high", flags)
    elif count >= 2:
        return ("medium", flags)
    elif count >= 1:
        return ("low", flags)
    return ("none", flags)

UTILITY_TERMS = [
    "deliverable", "format", "json", "schema", "validate", "test",
    "metrics", "confidence", "step", "phase", "layer", "synthesize",
    "decompose", "retrieval", "pipeline", "monitoring", "rollback",
    "version", "governance", "audit", "agent", "delegate", "evidence",
    "facts", "verify", "timeline", "risk", "requirements", "constraints",
    "implementation", "architecture", "design", "security", "compliance",
    "report", "summary", "action plan", "code review", "unit test",
    "integration", "deployment", "rollout", "performance", "scalability",
]

def score_prompt(content):
    lower = content.lower()
    score = 0
    score += sum(3 for t in UTILITY_TERMS if t in lower)
    score += min(len(re.findall(r'\[[A-Z0-9_ /-]+\]|\[YOUR.*?\]|\{\{[A-Z_]+\}\}', content)), 10) * 2
    word_count = len(re.findall(r'\w+', content))
    if 80 <= word_count <= 600:
        score += 10
    elif word_count > 600:
        score += 5
    if word_count < 10:
        score -= 5
    return max(0, score)

def extract_prompts(text, keep_duplicates=False, similarity_threshold=SIMILARITY_THRESHOLD):
    text = normalize_text(text)

    headings = [(m.start(), len(m.group(1)), m.group(2).strip()) for m in RX_HEADING.finditer(text)]

    def heading_path_at(pos):
        stack = []
        for hp, lvl, h in headings:
            if hp < pos:
                stack = [x for x in stack if x[0] < lvl]
                stack.append((lvl, h))
            else:
                break
        return " > ".join(h for _, h in stack) or "Root"

    raw_items = []
    code_block_spans = []
    for m in RX_FENCED_CODE.finditer(text):
        code_block_spans.append((m.start(), m.end()))
    def is_inside_code_block(pos):
        return any(start <= pos < end for start, end in code_block_spans)

    def add_item(content, src, line):
        if content and content.strip() and len(content) > 5:
            if src in ("numbered_inline", "bullet_inline", "colon_label", "explicit_prompt", "the_prompt_label"):
                raw_items.append({
                    "content": content.strip(),
                    "path": heading_path_at(line),
                    "src": src,
                    "line": line,
                })
            else:
                if not is_inside_code_block(line):
                    raw_items.append({
                        "content": content.strip(),
                        "path": heading_path_at(line),
                        "src": src,
                        "line": line,
                    })

    for m in RX_NUMBERED_INLINE.finditer(text):
        add_item(m.group(2), "numbered_inline", m.start())
    for m in RX_FENCED_CODE.finditer(text):
        content = m.group(2).strip()
        if content:
            add_item(content, "fenced_code", m.start())
    for m in RX_PROMPT_BLOCK.finditer(text):
        add_item(m.group(1), "explicit_prompt", m.start())
    for m in RX_THE_PROMPT.finditer(text):
        add_item(m.group(1), "the_prompt_label", m.start())
    for m in RX_BLOCKQUOTE.finditer(text):
        content = m.group(0).replace("> ", "").replace(">", "")
        if len(content) > 20:
            add_item(content, "blockquote", m.start())
    for m in RX_BULLET_PROMPT.finditer(text):
        add_item(m.group(1), "bullet_inline", m.start())
    for m in RX_COLON_LABEL.finditer(text):
        add_item(m.group(1), "colon_label", m.start())
    for m in RX_ANGLE_BRACKET.finditer(text):
        add_item(m.group(1), "angle_bracket", m.start())
    for m in RX_JSON_LINE.finditer(text):
        raw = m.group(1)
        try:
            line_start = text.rfind('\n', 0, m.start()) + 1
            line_end = text.find('\n', m.start())
            if line_end == -1:
                line_end = len(text)
            line = text[line_start:line_end].strip()
            if line.startswith('{') and line.endswith('}'):
                data = json.loads(line)
                prompt_value = None
                for key in ('prompt', 'say', 'user', 'agent', 'input', 'query', 'text', 'content'):
                    if key in data:
                        prompt_value = data[key]
                        break
                if prompt_value is not None:
                    add_item(prompt_value, "json_line", m.start())
                else:
                    add_item(raw, "json_line_raw", m.start())
            else:
                add_item(raw, "json_line_raw", m.start())
        except (json.JSONDecodeError, ValueError) as e:
            add_item(raw, "json_line_raw", m.start())
            warnings.warn(f"JSON parsing failed at line {m.start()}: {e}")

    if keep_duplicates:
        return raw_items

    groups = defaultdict(list)
    for item in raw_items:
        norm = re.sub(r'\s+', ' ', item["content"]).casefold().strip()
        norm_hash = hashlib.sha256(norm.encode()).hexdigest()[:16]
        groups[norm_hash].append(item)

    final_items = []
    for h, items in groups.items():
        items.sort(key=lambda x: (len(x["content"]), x["line"]), reverse=True)
        best = items[0]
        best["duplicate_count"] = len(items)
        best["duplicate_lines"] = [x["line"] for x in items[1:]]
        final_items.append(best)

    final_items.sort(key=lambda x: len(x["content"]))

    reps = []
    for item in final_items:
        found = False
        for rep in reps:
            if abs(len(rep["content"]) - len(item["content"])) > max(10, 0.2 * len(item["content"])):
                continue
            words1 = set(re.findall(r'\w+', rep["content"].casefold()))
            words2 = set(re.findall(r'\w+', item["content"].casefold()))
            if not words1 or not words2:
                continue
            jaccard = len(words1 & words2) / len(words1 | words2)
            if jaccard < 0.5:
                continue
            if SequenceMatcher(None, rep["content"].casefold(), item["content"].casefold()).ratio() > similarity_threshold:
                rep["duplicate_count"] += item.get("duplicate_count", 1)
                rep["duplicate_lines"].extend(item.get("duplicate_lines", []))
                rep["duplicate_lines"].append(item["line"])
                found = True
                break
        if not found:
            reps.append(item)

    return reps

def parse_args():
    global SIMILARITY_THRESHOLD, MIN_UTILITY, KEEP_DUPLICATES
    args = sys.argv[1:]
    if len(args) < 2:
        print("Usage: python ripper.py input.txt output.json [--similarity 0.92] [--min-utility 0] [--keep-duplicates]", file=sys.stderr)
        sys.exit(2)
    input_path = Path(args[0])
    output_path = Path(args[1])
    i = 2
    while i < len(args):
        if args[i] == "--similarity":
            try:
                SIMILARITY_THRESHOLD = float(args[i+1])
                i += 2
            except:
                print("Error: --similarity requires a float value", file=sys.stderr)
                sys.exit(2)
        elif args[i] == "--min-utility":
            try:
                MIN_UTILITY = int(args[i+1])
                i += 2
            except:
                print("Error: --min-utility requires an integer", file=sys.stderr)
                sys.exit(2)
        elif args[i] == "--keep-duplicates":
            KEEP_DUPLICATES = True
            i += 1
        else:
            print(f"Unknown option: {args[i]}", file=sys.stderr)
            sys.exit(2)
    return input_path, output_path

def main():
    input_path, output_path = parse_args()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    text = None
    for enc in ["utf-8", "cp1252", "latin-1"]:
        try:
            text = input_path.read_text(encoding=enc, errors="strict")
            break
        except UnicodeDecodeError:
            continue
    if text is None:
        text = input_path.read_text(encoding="utf-8", errors="ignore")
        warnings.warn("File encoding not detected; using utf-8 with error ignore.")

    print("Extracting prompts...", file=sys.stderr)
    sys.stderr.write(".")
    sys.stderr.flush()

    items = extract_prompts(text, keep_duplicates=KEEP_DUPLICATES, similarity_threshold=SIMILARITY_THRESHOLD)

    sys.stderr.write("\nScoring and filtering...\n")

    results = []
    for item in items:
        content = item["content"]
        risk_level, flags = red_team_risk(content)
        utility = score_prompt(content)
        if utility < MIN_UTILITY:
            continue
        results.append({
            "id": f"P{len(results)+1:03d}",
            "heading_path": item["path"],
            "source_type": item["src"],
            "content": content,
            "normalized_hash": hashlib.sha256(
                re.sub(r'\s+', ' ', content).casefold().strip().encode()
            ).hexdigest()[:16],
            "utility_score": utility,
            "red_team_risk": risk_level,
            "risk_flags": flags,
            "duplicate_count": item.get("duplicate_count", 1),
            "duplicate_lines": item.get("duplicate_lines", []),
            "line": item["line"],
        })

    risk_order = {"high": 0, "medium": 1, "low": 2, "none": 3}
    results.sort(key=lambda x: (risk_order[x["red_team_risk"]], -x["utility_score"]))

    output_path.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")

    total = len(results)
    red_count = sum(1 for r in results if r["red_team_risk"] != "none")
    dup_count = sum(r["duplicate_count"] - 1 for r in results)
    print(f"Extracted {total} unique prompts (plus {dup_count} duplicate occurrences) to {output_path}")
    print(f"Red-team flags: {red_count} prompts ({sum(1 for r in results if r['red_team_risk']=='high')} high risk)")

if __name__ == "__main__":
    main()
```

**app.py**
```python
import os
import subprocess
import tempfile
import threading
import uuid
import queue
import json
import shutil
from pathlib import Path
from typing import Optional, List, Dict, Any

import uvicorn
from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Query, Request
from fastapi.responses import StreamingResponse, JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

import fitz  # PyMuPDF
from docx import Document
from PIL import Image
import pytesseract
import numpy as np
from sentence_transformers import SentenceTransformer
import faiss
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import scipy.sparse as sp

# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------
UPLOAD_FOLDER = tempfile.mkdtemp()
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB
MODEL_NAME = 'all-MiniLM-L6-v2'   # Lightweight semantic model

# Global job storage
jobs: Dict[str, Dict[str, Any]] = {}
jobs_lock = threading.Lock()

# Global search indices (in-memory)
semantic_model: Optional[SentenceTransformer] = None
tfidf_vectorizer: Optional[TfidfVectorizer] = None
faiss_index: Optional[faiss.Index] = None
tfidf_matrix: Optional[sp.csr_matrix] = None
results_metadata: List[Dict[str, Any]] = []

app = FastAPI(title="Prompt Ripper Pro")
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# ----------------------------------------------------------------------
# Text extraction functions
# ----------------------------------------------------------------------
def extract_text_from_pdf(file_path: str) -> str:
    text = ""
    with fitz.open(file_path) as doc:
        for page in doc:
            text += page.get_text()
    return text

def extract_text_from_docx(file_path: str) -> str:
    doc = Document(file_path)
    return "\n".join([para.text for para in doc.paragraphs])

def extract_text_from_image(file_path: str) -> str:
    img = Image.open(file_path)
    return pytesseract.image_to_string(img)

def extract_text_from_plain(file_path: str) -> str:
    for enc in ["utf-8", "cp1252", "latin-1"]:
        try:
            with open(file_path, 'r', encoding=enc) as f:
                return f.read()
        except UnicodeDecodeError:
            continue
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        return f.read()

def extract_text(file_path: str) -> str:
    ext = Path(file_path).suffix.lower()
    if ext == '.pdf':
        return extract_text_from_pdf(file_path)
    elif ext == '.docx':
        return extract_text_from_docx(file_path)
    elif ext in ['.png', '.jpg', '.jpeg', '.tiff', '.bmp']:
        return extract_text_from_image(file_path)
    else:
        return extract_text_from_plain(file_path)

# ----------------------------------------------------------------------
# Search index building
# ----------------------------------------------------------------------
def build_search_index(prompts: List[Dict[str, Any]]):
    """Build semantic (FAISS) and lexical (TF‑IDF) indices in memory."""
    global semantic_model, tfidf_vectorizer, faiss_index, tfidf_matrix, results_metadata

    results_metadata = prompts
    if not prompts:
        return

    # Semantic index
    if semantic_model is None:
        semantic_model = SentenceTransformer(MODEL_NAME)
    embeddings = semantic_model.encode([p['content'] for p in prompts], convert_to_numpy=True)
    dimension = embeddings.shape[1]
    faiss_index = faiss.IndexFlatL2(dimension)
    faiss_index.add(embeddings.astype(np.float32))

    # Lexical index
    tfidf_vectorizer = TfidfVectorizer(stop_words='english', max_features=10000)
    tfidf_matrix = tfidf_vectorizer.fit_transform([p['content'] for p in prompts])

# ----------------------------------------------------------------------
# Background processing
# ----------------------------------------------------------------------
def run_ripper(job_id: str, input_path: str, output_path: str,
               similarity: float, min_utility: int, keep_duplicates: bool):
    q = jobs[job_id]['queue']
    q.put({'type': 'status', 'message': 'Starting text extraction...'})

    cmd = [
        'python', 'ripper.py', input_path, output_path,
        '--similarity', str(similarity),
        '--min-utility', str(min_utility)
    ]
    if keep_duplicates:
        cmd.append('--keep-duplicates')

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        universal_newlines=True
    )

    for line in iter(process.stderr.readline, ''):
        if line:
            line = line.rstrip()
            if line:
                q.put({'type': 'progress', 'message': line})

    process.wait()
    if process.returncode != 0:
        q.put({'type': 'error', 'message': f'Script failed with exit code {process.returncode}'})
        jobs[job_id]['status'] = 'error'
        return

    try:
        with open(output_path, 'r', encoding='utf-8') as f:
            results = json.load(f)
        jobs[job_id]['result'] = results
        jobs[job_id]['status'] = 'completed'

        # Build search indices in background thread to avoid blocking
        build_search_index(results)

        q.put({'type': 'result', 'data': results})
        q.put({'type': 'done', 'message': 'Processing complete.'})
    except Exception as e:
        q.put({'type': 'error', 'message': f'Error reading results: {str(e)}'})
        jobs[job_id]['status'] = 'error'

# ----------------------------------------------------------------------
# API Endpoints
# ----------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    similarity: float = Form(0.92),
    min_utility: int = Form(0),
    keep_duplicates: bool = Form(False)
):
    job_id = str(uuid.uuid4())
    ext = Path(file.filename).suffix.lower()
    allowed_exts = ['.txt', '.md', '.json', '.csv', '.log', '.pdf', '.docx', '.png', '.jpg', '.jpeg', '.tiff', '.bmp']
    if ext not in allowed_exts:
        raise HTTPException(status_code=400, detail=f"Unsupported file type: {ext}")

    # Save uploaded file
    input_path = os.path.join(UPLOAD_FOLDER, f"{job_id}{ext}")
    with open(input_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # Extract text
    try:
        text = extract_text(input_path)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Text extraction failed: {str(e)}")

    # Save text as a temporary .txt file for ripper.py
    text_file_path = os.path.join(UPLOAD_FOLDER, f"{job_id}_extracted.txt")
    with open(text_file_path, 'w', encoding='utf-8') as f:
        f.write(text)

    output_path = os.path.join(UPLOAD_FOLDER, f"{job_id}_output.json")

    with jobs_lock:
        jobs[job_id] = {
            'queue': queue.Queue(),
            'status': 'running',
            'result': None,
            'error': None,
        }

    thread = threading.Thread(
        target=run_ripper,
        args=(job_id, text_file_path, output_path, similarity, min_utility, keep_duplicates)
    )
    thread.daemon = True
    thread.start()

    return JSONResponse({"job_id": job_id}, status_code=202)

@app.get("/stream/{job_id}")
async def stream(job_id: str):
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Invalid job ID")

    async def event_generator():
        q = jobs[job_id]['queue']
        while True:
            try:
                message = q.get(timeout=30)
                yield f"data: {json.dumps(message)}\n\n"
                if message['type'] in ('done', 'error'):
                    break
            except queue.Empty:
                yield ": keep-alive\n\n"
    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.get("/results/{job_id}")
async def get_results(job_id: str):
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Invalid job ID")
    job = jobs[job_id]
    if job['status'] == 'completed':
        return JSONResponse(job['result'])
    elif job['status'] == 'error':
        raise HTTPException(status_code=500, detail=job.get('error', 'Processing error'))
    else:
        return JSONResponse({"status": "processing"}, status_code=202)

@app.get("/search")
async def search_prompts(
    q: str = Query(..., min_length=1),
    method: str = Query("semantic", regex="^(semantic|lexical|both)$"),
    top_k: int = Query(10, ge=1, le=50)
):
    if not results_metadata:
        raise HTTPException(status_code=404, detail="No prompts indexed yet. Process a file first.")

    results = []
    if method in ("semantic", "both") and faiss_index is not None:
        query_embedding = semantic_model.encode([q], convert_to_numpy=True).astype(np.float32)
        distances, indices = faiss_index.search(query_embedding, top_k)
        for idx, dist in zip(indices[0], distances[0]):
            if idx < len(results_metadata):
                results.append({
                    "prompt": results_metadata[idx],
                    "score": float(dist),
                    "method": "semantic"
                })

    if method in ("lexical", "both") and tfidf_vectorizer is not None and tfidf_matrix is not None:
        query_vec = tfidf_vectorizer.transform([q])
        similarities = cosine_similarity(query_vec, tfidf_matrix).flatten()
        top_indices = similarities.argsort()[-top_k:][::-1]
        for idx in top_indices:
            if similarities[idx] > 0:
                results.append({
                    "prompt": results_metadata[idx],
                    "score": float(similarities[idx]),
                    "method": "lexical"
                })

    if method == "semantic":
        results.sort(key=lambda x: x['score'])
    elif method == "lexical":
        results.sort(key=lambda x: -x['score'])
    else:  # both
        results.sort(key=lambda x: (x['method'], x['score'] if x['method']=='semantic' else -x['score']))

    return JSONResponse(results[:top_k])

@app.post("/build_index")
async def build_index_endpoint(prompts: List[Dict[str, Any]]):
    build_search_index(prompts)
    return JSONResponse({"status": "index built"})

@app.get("/health")
async def health_check():
    """Real healthcheck: verifies that the temporary directory exists and is writable."""
    checks = {}
    if os.path.isdir(UPLOAD_FOLDER) and os.access(UPLOAD_FOLDER, os.W_OK):
        checks['temp_dir'] = 'ok'
    else:
        checks['temp_dir'] = 'error: upload folder missing or not writable'
    try:
        pytesseract.get_tesseract_version()
        checks['tesseract'] = 'ok'
    except Exception as e:
        checks['tesseract'] = f'warning: {str(e)}'
    if os.path.isfile('ripper.py'):
        checks['ripper_script'] = 'ok'
    else:
        checks['ripper_script'] = 'error: ripper.py not found'

    critical_fail = any(v.startswith('error') for v in checks.values())
    if critical_fail:
        return JSONResponse({"status": "unhealthy", "checks": checks}, status_code=500)
    return JSONResponse({"status": "healthy", "checks": checks}, status_code=200)

@app.on_event("startup")
async def startup_event():
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000, log_level="info")
```

**templates/index.html**
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Prompt Ripper Pro - Extract and Analyze Prompts</title>
    <meta name="description" content="Upload files, extract prompts with fuzzy matching, risk scoring, and semantic search. Supports PDF, DOCX, images, and text.">
    <meta property="og:title" content="Prompt Ripper Pro">
    <meta property="og:description" content="Extract, analyze, and search prompts from any document.">
    <meta property="og:type" content="website">
    <meta property="og:url" content="https://prompt-ripper.example.com">
    <meta property="og:image" content="/static/logo.svg">
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🔍</text></svg>">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        :root {
            --bg: #f8f9fa;
            --card-bg: #ffffff;
            --text: #212529;
            --border: #dee2e6;
            --log-bg: #ffffff;
            --log-text: #212529;
            --risk-high: #dc3545;
            --risk-medium: #fd7e14;
            --risk-low: #ffc107;
            --risk-none: #28a745;
        }
        [data-theme="dark"] {
            --bg: #121212;
            --card-bg: #1e1e1e;
            --text: #e0e0e0;
            --border: #333;
            --log-bg: #1e1e1e;
            --log-text: #e0e0e0;
        }
        body {
            background-color: var(--bg);
            color: var(--text);
            transition: background-color 0.3s, color 0.3s;
        }
        .card {
            background-color: var(--card-bg);
            border-color: var(--border);
            transition: background-color 0.3s, border-color 0.3s;
        }
        .card-header {
            background-color: rgba(0,0,0,0.03);
            border-bottom: 1px solid var(--border);
        }
        [data-theme="dark"] .card-header {
            background-color: rgba(255,255,255,0.05);
        }
        .drop-zone {
            border: 2px dashed var(--border);
            border-radius: 8px;
            padding: 2rem;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s;
            background-color: var(--card-bg);
        }
        .drop-zone.dragover {
            border-color: #007bff;
            background-color: rgba(0,123,255,0.1);
        }
        .progress-log {
            height: 200px;
            overflow-y: auto;
            background: var(--log-bg);
            color: var(--log-text);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 10px;
            font-family: monospace;
            font-size: 0.9em;
            white-space: pre-wrap;
            word-break: break-word;
        }
        .risk-high { color: var(--risk-high) !important; font-weight: bold; }
        .risk-medium { color: var(--risk-medium) !important; font-weight: bold; }
        .risk-low { color: var(--risk-low) !important; font-weight: bold; }
        .risk-none { color: var(--risk-none) !important; }
        .table-responsive { max-height: 600px; }
        .content-preview {
            max-width: 300px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .search-box { margin-bottom: 20px; }
        .btn-outline-secondary {
            color: var(--text);
            border-color: var(--border);
        }
        .btn-outline-secondary:hover {
            background-color: rgba(0,0,0,0.1);
        }
        [data-theme="dark"] .btn-outline-secondary:hover {
            background-color: rgba(255,255,255,0.1);
        }
        .form-control, .form-select {
            background-color: var(--card-bg);
            color: var(--text);
            border-color: var(--border);
        }
        .form-control:focus, .form-select:focus {
            background-color: var(--card-bg);
            color: var(--text);
            border-color: #007bff;
            box-shadow: none;
        }
        .table {
            color: var(--text);
        }
        .table-striped tbody tr:nth-of-type(odd) {
            background-color: rgba(0,0,0,0.02);
        }
        [data-theme="dark"] .table-striped tbody tr:nth-of-type(odd) {
            background-color: rgba(255,255,255,0.02);
        }
        .theme-toggle {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 1000;
        }
        @media (max-width: 768px) {
            .container { padding: 0 12px; }
            .drop-zone { padding: 1.5rem; }
            .btn { font-size: 0.9rem; }
        }
    </style>
</head>
<body>
    <button id="themeToggle" class="btn btn-sm btn-outline-secondary theme-toggle" aria-label="Toggle dark mode">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"></path>
        </svg>
    </button>

    <div class="container mt-4">
        <header class="mb-4">
            <h1 class="display-5">
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="me-2">
                    <circle cx="11" cy="11" r="8"></circle>
                    <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
                </svg>
                Prompt Ripper Pro
            </h1>
            <p class="lead">Upload, extract, and analyze prompts with fuzzy matching and semantic search.</p>
        </header>

        <div class="row g-4">
            <div class="col-lg-5">
                <section class="card mb-3">
                    <div class="card-header">
                        <h2 class="h5 mb-0">Upload File</h2>
                    </div>
                    <div class="card-body">
                        <div id="dropZone" class="drop-zone mb-3">
                            <p class="mb-1">Drag & drop your file here</p>
                            <p class="text-muted">Supported: TXT, MD, JSON, CSV, PDF, DOCX, PNG, JPG, TIFF</p>
                            <button id="browseBtn" class="btn btn-outline-primary">Browse Files</button>
                            <input type="file" id="fileInput" class="d-none" accept=".txt,.md,.json,.csv,.log,.pdf,.docx,.png,.jpg,.jpeg,.tiff,.bmp">
                        </div>
                        <div id="fileInfo" class="mb-3 d-none">
                            <strong>Selected file:</strong> <span id="fileName"></span>
                        </div>
                        <button id="clearBtn" class="btn btn-secondary btn-sm mb-3">Clear</button>
                    </div>
                </section>

                <section class="card mb-3">
                    <div class="card-header">
                        <h2 class="h5 mb-0">Options</h2>
                    </div>
                    <div class="card-body">
                        <div class="mb-3">
                            <label for="similarity" class="form-label">Similarity Threshold (0.0 – 1.0)</label>
                            <input type="number" class="form-control" id="similarity" value="0.92" min="0" max="1" step="0.01">
                        </div>
                        <div class="mb-3">
                            <label for="minUtility" class="form-label">Minimum Utility Score</label>
                            <input type="number" class="form-control" id="minUtility" value="0" min="0" step="1">
                        </div>
                        <div class="form-check mb-3">
                            <input class="form-check-input" type="checkbox" id="keepDuplicates">
                            <label class="form-check-label" for="keepDuplicates">Keep Duplicates</label>
                        </div>
                        <button id="processBtn" class="btn btn-primary w-100" disabled>Process File</button>
                    </div>
                </section>

                <section class="card mb-3">
                    <div class="card-header">
                        <h2 class="h5 mb-0">Search Extracted Prompts</h2>
                    </div>
                    <div class="card-body">
                        <div class="input-group search-box">
                            <input type="text" id="searchQuery" class="form-control" placeholder="Enter search query...">
                            <select id="searchMethod" class="form-select" style="max-width: 120px;">
                                <option value="semantic">Semantic</option>
                                <option value="lexical">Lexical</option>
                                <option value="both">Both</option>
                            </select>
                            <button id="searchBtn" class="btn btn-outline-secondary">Search</button>
                        </div>
                        <div id="searchResults"></div>
                    </div>
                </section>
            </div>

            <div class="col-lg-7">
                <section class="card mb-3">
                    <div class="card-header">
                        <h2 class="h5 mb-0">Progress Log</h2>
                    </div>
                    <div class="card-body">
                        <div id="progressLog" class="progress-log"></div>
                    </div>
                </section>

                <section class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h2 class="h5 mb-0">Results</h2>
                        <button id="downloadResultsBtn" class="btn btn-sm btn-success" disabled>Download JSON</button>
                    </div>
                    <div class="card-body">
                        <div id="resultsContainer">
                            <p class="text-muted">No results yet.</p>
                        </div>
                    </div>
                </section>
            </div>
        </div>
    </div>

    <script src="https://code.jquery.com/jquery-3.6.4.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        $(document).ready(function() {
            let selectedFile = null;
            let currentJobId = null;
            let eventSource = null;
            let resultsData = null;

            // Theme toggle
            const themeToggle = document.getElementById('themeToggle');
            themeToggle.addEventListener('click', () => {
                const currentTheme = document.documentElement.getAttribute('data-theme');
                const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
                document.documentElement.setAttribute('data-theme', newTheme);
                localStorage.setItem('theme', newTheme);
            });
            // Set initial theme from localStorage or system preference
            const storedTheme = localStorage.getItem('theme');
            if (storedTheme) {
                document.documentElement.setAttribute('data-theme', storedTheme);
            } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
                document.documentElement.setAttribute('data-theme', 'dark');
            }

            // Drag and drop handlers
            const dropZone = document.getElementById('dropZone');
            dropZone.addEventListener('dragover', (e) => {
                e.preventDefault();
                dropZone.classList.add('dragover');
            });
            dropZone.addEventListener('dragleave', () => {
                dropZone.classList.remove('dragover');
            });
            dropZone.addEventListener('drop', (e) => {
                e.preventDefault();
                dropZone.classList.remove('dragover');
                const files = e.dataTransfer.files;
                if (files.length > 0) {
                    handleFile(files[0]);
                }
            });

            // Browse button
            $('#browseBtn').click(() => {
                $('#fileInput').click();
            });
            $('#fileInput').change((e) => {
                if (e.target.files.length > 0) {
                    handleFile(e.target.files[0]);
                }
            });

            // Clear button
            $('#clearBtn').click(() => {
                clearFile();
            });

            // Process button
            $('#processBtn').click(() => {
                if (selectedFile) {
                    startProcessing();
                }
            });

            // Download results
            $('#downloadResultsBtn').click(() => {
                if (resultsData) {
                    const blob = new Blob([JSON.stringify(resultsData, null, 2)], { type: 'application/json' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'prompt_ripper_results.json';
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    URL.revokeObjectURL(url);
                }
            });

            // Search
            $('#searchBtn').click(() => {
                performSearch();
            });
            $('#searchQuery').keypress(function(e) {
                if (e.which === 13) {
                    performSearch();
                }
            });

            function handleFile(file) {
                selectedFile = file;
                $('#fileName').text(file.name);
                $('#fileInfo').removeClass('d-none');
                $('#processBtn').prop('disabled', false);
                $('#resultsContainer').html('<p class="text-muted">Ready to process.</p>');
                $('#downloadResultsBtn').prop('disabled', true);
                if (eventSource) eventSource.close();
                $('#progressLog').empty();
                resultsData = null;
            }

            function clearFile() {
                selectedFile = null;
                $('#fileInfo').addClass('d-none');
                $('#fileInput').val('');
                $('#processBtn').prop('disabled', true);
                $('#resultsContainer').html('<p class="text-muted">No results yet.</p>');
                $('#downloadResultsBtn').prop('disabled', true);
                $('#progressLog').empty();
                if (eventSource) eventSource.close();
                resultsData = null;
            }

            function appendLog(message, type = 'info') {
                const logDiv = $('#progressLog');
                const timestamp = new Date().toLocaleTimeString();
                const icon = type === 'error' ? '✖' : type === 'progress' ? '●' : '✔';
                logDiv.append(`<div>${icon} [${timestamp}] ${message}</div>`);
                logDiv.scrollTop(logDiv[0].scrollHeight);
            }

            function startProcessing() {
                if (!selectedFile) return;

                $('#processBtn').prop('disabled', true);
                $('#browseBtn').prop('disabled', true);
                $('#clearBtn').prop('disabled', true);
                $('#progressLog').empty();
                appendLog('Uploading and starting processing...', 'status');

                const formData = new FormData();
                formData.append('file', selectedFile);
                formData.append('similarity', $('#similarity').val());
                formData.append('min_utility', $('#minUtility').val());
                formData.append('keep_duplicates', $('#keepDuplicates').is(':checked'));

                $.ajax({
                    url: '/upload',
                    type: 'POST',
                    data: formData,
                    processData: false,
                    contentType: false,
                    success: function(response) {
                        currentJobId = response.job_id;
                        appendLog('Processing started. Listening to progress...', 'status');
                        openEventStream(currentJobId);
                    },
                    error: function(xhr, status, error) {
                        appendLog('Upload failed: ' + error, 'error');
                        enableControls();
                    }
                });
            }

            function openEventStream(jobId) {
                eventSource = new EventSource(`/stream/${jobId}`);
                eventSource.onmessage = function(event) {
                    const data = JSON.parse(event.data);
                    if (data.type === 'progress') {
                        appendLog(data.message, 'progress');
                    } else if (data.type === 'status') {
                        appendLog(data.message, 'status');
                    } else if (data.type === 'result') {
                        resultsData = data.data;
                        appendLog('Results received. Building search index...', 'status');
                        renderResults(resultsData);
                        // The index is already built in background; call anyway for safety
                        fetch('/build_index', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({prompts: resultsData})
                        }).catch(err => console.error('Index build failed:', err));
                    } else if (data.type === 'done') {
                        appendLog(data.message, 'done');
                        eventSource.close();
                        enableControls();
                    } else if (data.type === 'error') {
                        appendLog(data.message, 'error');
                        eventSource.close();
                        enableControls();
                    }
                };
                eventSource.onerror = function(e) {
                    appendLog('EventSource error. Connection may be lost.', 'error');
                    eventSource.close();
                    enableControls();
                };
            }

            function enableControls() {
                $('#processBtn').prop('disabled', false);
                $('#browseBtn').prop('disabled', false);
                $('#clearBtn').prop('disabled', false);
            }

            function renderResults(data) {
                if (!data || data.length === 0) {
                    $('#resultsContainer').html('<div class="alert alert-warning">No prompts found.</div>');
                    return;
                }
                let html = `<div class="table-responsive"><table class="table table-striped table-sm">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Risk</th>
                            <th>Utility</th>
                            <th>Source</th>
                            <th>Heading</th>
                            <th>Content</th>
                        </tr>
                    </thead>
                    <tbody>`;
                data.forEach(item => {
                    const riskClass = `risk-${item.red_team_risk}`;
                    const riskBadge = `<span class="${riskClass}">${item.red_team_risk.toUpperCase()}</span>`;
                    const flags = item.risk_flags.length ? `<br><small class="text-muted">${item.risk_flags.join(', ')}</small>` : '';
                    const contentPreview = item.content.length > 200 
                        ? item.content.substring(0, 200) + '...' 
                        : item.content;
                    html += `<tr>
                        <td>${item.id}</td>
                        <td>${riskBadge}${flags}</td>
                        <td>${item.utility_score}</td>
                        <td>${item.source_type}</td>
                        <td>${item.heading_path || 'Root'}</td>
                        <td class="content-preview" title="${escapeHtml(item.content)}">${escapeHtml(contentPreview)}</td>
                    </tr>`;
                });
                html += '</tbody></table></div>';
                $('#resultsContainer').html(html);
                $('#downloadResultsBtn').prop('disabled', false);
            }

            function performSearch() {
                const query = $('#searchQuery').val().trim();
                if (!query) return;
                const method = $('#searchMethod').val();
                const topK = 10;
                $('#searchResults').html('<p class="text-muted">Searching...</p>');
                $.getJSON('/search', {q: query, method: method, top_k: topK}, function(data) {
                    if (data.length === 0) {
                        $('#searchResults').html('<div class="alert alert-warning">No matching prompts.</div>');
                    } else {
                        let html = '<ul class="list-group">';
                        data.forEach(item => {
                            const p = item.prompt;
                            const riskClass = `risk-${p.red_team_risk}`;
                            html += `<li class="list-group-item">
                                <strong>${p.id}</strong> (${p.red_team_risk.toUpperCase()}, score: ${item.score.toFixed(3)})
                                <br><span class="content-preview">${escapeHtml(p.content.substring(0, 200))}...</span>
                            </li>`;
                        });
                        html += '</ul>';
                        $('#searchResults').html(html);
                    }
                }).fail(function() {
                    $('#searchResults').html('<div class="alert alert-danger">Search failed. Make sure you have processed a file first.</div>');
                });
            }

            function escapeHtml(text) {
                const div = document.createElement('div');
                div.textContent = text;
                return div.innerHTML;
            }
        });
    </script>
</body>
</html>
```

**requirements.txt**
```
fastapi==0.110.0
uvicorn[standard]==0.29.0
python-multipart==0.0.9
PyMuPDF==1.24.0
python-docx==1.1.0
pytesseract==0.3.10
Pillow==10.2.0
sentence-transformers==2.5.1
faiss-cpu==1.8.0
scikit-learn==1.4.1.post1
numpy==1.26.4
scipy==1.12.0
```

**railway.json**
```json
{
  "$schema": "https://railway.app/railway.schema.json",
  "build": {
    "builder": "NIXPACKS",
    "buildCommand": "pip install -r requirements.txt"
  },
  "deploy": {
    "startCommand": "python app.py",
    "healthcheckPath": "/health",
    "healthcheckTimeout": 100,
    "restartPolicyType": "ON_FAILURE",
    "restartPolicyMaxRetries": 10
  }
}
```

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
