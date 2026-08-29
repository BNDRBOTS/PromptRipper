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
