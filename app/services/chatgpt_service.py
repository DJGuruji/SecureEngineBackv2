"""
chatgpt_service.py
------------------
Static-analysis helper that sends code to OpenAI Chat Completions
(gpt-4o-mini by default) and normalises the result into Semgrep-style
findings so the rest of the pipeline stays unchanged.
"""
from __future__ import annotations

import os
import json
import logging
import tempfile
import shutil
import zipfile
import re
from typing import Dict, Any, List, Tuple

from dotenv import load_dotenv
from openai import AsyncOpenAI, OpenAIError

from app.core.scan_exclusions import should_exclude_path

# --------------------------------------------------------------------------
load_dotenv()
OPENAI_API_KEY = os.getenv("CHATGPT_API_KEY")
if not OPENAI_API_KEY:
    raise RuntimeError("CHATGPT_API_KEY is not set in the environment")

client = AsyncOpenAI(api_key=OPENAI_API_KEY)
MODEL_NAME = os.getenv("CHATGPT_MODEL", "gpt-4o-mini")

logger = logging.getLogger(__name__)
# --------------------------------------------------------------------------


# ──────────────────────────────────────────────────────────────────────────
#  Public entry point
# ──────────────────────────────────────────────────────────────────────────
async def scan_code_with_chatgpt(file_path: str) -> Dict[str, Any]:
    """
    Expand archives (if needed), read code files, submit them to ChatGPT,
    and return a vulnerability report in the same schema used previously.
    """
    logger.info("ChatGPT scan started for %s", file_path)

    # 1️⃣ Extract *.zip if supplied
    extracted_path, temp_dir = _prepare_source(file_path)

    try:
        file_contents, logical_paths = _get_file_contents(extracted_path)
        if not file_contents:
            raise ValueError("No code files found to analyse")

        vulnerabilities = await _analyse_files_with_chatgpt(file_contents)

        total = len(vulnerabilities)
        severity_count = _count_by_severity(vulnerabilities)
        security_score = _calculate_security_score(vulnerabilities)

        return {
            "file_name": os.path.basename(file_path),
            "security_score": security_score,
            "vulnerabilities": vulnerabilities,
            "severity_count": severity_count,
            "total_vulnerabilities": total,
            "scan_metadata": {"scan_type": "AI", "scan_mode": "chatgpt"},
        }

    finally:
        # Clean-up any temp extraction
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)


# ──────────────────────────────────────────────────────────────────────────
#  Helpers
# ──────────────────────────────────────────────────────────────────────────
def _prepare_source(file_path: str) -> Tuple[str, str | None]:
    """If *file_path* is a .zip, extract it and return new path + temp dir."""
    if os.path.isfile(file_path) and file_path.endswith(".zip"):
        temp_dir = tempfile.mkdtemp()
        with zipfile.ZipFile(file_path, "r") as zf:
            zf.extractall(temp_dir)
        return temp_dir, temp_dir
    return file_path, None


def _get_file_contents(path: str) -> Tuple[Dict[str, str], List[str]]:
    """Recursively read code files, skipping exclusions, return {path:code}."""
    code_exts = {
        ".py", ".js", ".ts", ".java", ".cpp", ".c", ".cs",
        ".php", ".rb", ".go", ".rs", ".html", ".css", ".jsx",
        ".tsx", ".vue", ".swift", ".kt", ".scala", ".sh",
        ".sql", ".dart", ".yaml", ".yml",
    }
    contents: Dict[str, str] = {}
    logical: List[str] = []

    if os.path.isfile(path):
        _maybe_add_file(path, contents, logical, code_exts)
    else:
        for root, dirs, files in os.walk(path):
            # prune excluded dirs
            dirs[:] = [d for d in dirs if not should_exclude_path(os.path.join(root, d))]
            for f in files:
                _maybe_add_file(os.path.join(root, f), contents, logical, code_exts, root)

    logger.info("Collected %d source files for ChatGPT", len(contents))
    return contents, logical


def _maybe_add_file(
    file_path: str,
    contents: Dict[str, str],
    logical: List[str],
    exts: set[str],
    base: str | None = None,
):
    if should_exclude_path(file_path):
        return
    _, ext = os.path.splitext(file_path)
    if ext in exts:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
                rel = os.path.relpath(file_path, base or os.path.dirname(file_path))
                contents[rel] = fh.read()
                logical.append(rel)
        except Exception as err:  # pragma: no cover
            logger.warning("Cannot read %s – %s", file_path, err)


# ──────────────────────────────────────────────────────────────────────────
async def _analyse_files_with_chatgpt(file_contents: Dict[str, str]) -> List[Dict[str, Any]]:
    """
    Loop through files, ask ChatGPT for a vulnerability list per file,
    sanitise/normalise responses, and aggregate them.
    """
    vulns: List[Dict[str, Any]] = []

    for path, code in file_contents.items():
        if len(code) > 80_000:  # keep prompt under token-limit margin
            logger.warning("Skipping %s – too large for model", path)
            continue

        prompt = _build_prompt(path, code)
        try:
            resp = await client.chat.completions.create(
                model=MODEL_NAME,
                messages=prompt,
                temperature=0.1,
                top_p=0.8,
                max_tokens=4096,
            )
            raw = resp.choices[0].message.content
            file_vulns = _parse_chatgpt_json(raw)
            vulns.extend(_normalise_vulns(file_vulns, path))

        except OpenAIError as api_err:  # pragma: no cover
            logger.warning("OpenAI error for %s – %s", path, api_err)
        except Exception as e:  # pragma: no cover
            logger.warning("Failed analysing %s – %s", path, e)

    # Fallback pattern matcher if zero vulns
    if not vulns and file_contents:
        vulns = _pattern_fallback(file_contents)

    if not vulns:
        first = next(iter(file_contents))
        vulns.append(
            {
                "check_id": "ai.security.no_issues",
                "path": first,
                "start": {"line": 1, "col": 1},
                "end": {"line": 1, "col": 1},
                "extra": {
                    "severity": "INFO",
                    "message": "No security vulnerabilities detected",
                    "metadata": {"category": "Security", "score": 10},
                    "score": 10,
                },
                "severity": "info",
            }
        )

    logger.info("Total vulnerabilities returned: %d", len(vulns))
    return vulns


def _build_prompt(path: str, code: str) -> List[Dict[str, str]]:
    """Return ChatML message list."""
    system_msg = (
        "You are a senior application-security engineer. "
        "Return findings strictly as JSON – no prose."
    )
    user_msg = f"""
Analyse the following file for *any* security vulnerability.

Return **only** a JSON array; for each finding use:
- "check_id": slug (e.g., "sql-injection")
- "path": file path as provided
- "line": integer line number
- "message": short description
- "severity": "ERROR" | "WARNING" | "INFO"
- "category": broad category (e.g., "Injection")
- "snippet": code snippet
- "score": 1-10 integer

File: {path}

```{code}```
"""
    return [
        {"role": "system", "content": system_msg},
        {"role": "user", "content": user_msg},
    ]


def _parse_chatgpt_json(raw: str) -> List[Dict[str, Any]]:
    """Extract and load the JSON array from ChatGPT's response."""
    # strip code-fences if any
    if "```" in raw:
        raw = raw.split("```")[1].strip()
    try:
        data = json.loads(raw)
        return data if isinstance(data, list) else []
    except json.JSONDecodeError:
        logger.debug("Malformed JSON, trying salvage")
        match = re.search(r"\[.*]", raw, re.S)
        return json.loads(match.group(0)) if match else []


def _normalise_vulns(vulns: List[Dict[str, Any]], path: str) -> List[Dict[str, Any]]:
    """Convert raw ChatGPT items into Semgrep-style dicts."""
    normalised = []
    for v in vulns:
        score = max(1, min(int(v.get("score", 5)), 10))
        severity = v.get("severity", "INFO").upper()
        # map score ↔ severity for consistency
        if score >= 7:
            severity = "ERROR"
        elif score >= 4:
            severity = "WARNING"
        else:
            severity = "INFO"
        # skip env-var snippets – same rule as before
        snippet = v.get("snippet", "")
        if any(
            pat in snippet
            for pat in ("os.getenv(", "os.environ.get(", "os.environ[")
        ):
            continue
        normalised.append(
            {
                "check_id": v.get("check_id", "ai.security.generic"),
                "path": path,
                "start": {"line": v.get("line", 1), "col": 1},
                "end": {"line": v.get("line", 1) + 1, "col": 80},
                "extra": {
                    "severity": severity,
                    "metadata": {
                        "category": v.get("category", "Security"),
                        "technology": ["AI", "ChatGPT"],
                        "score": score,
                    },
                    "message": v.get("message", "Potential issue"),
                    "lines": snippet,
                    "score": score,
                },
                "severity": severity.lower(),
            }
        )
    return normalised


# ──────────────────────────────────────────────────────────────────────────
#  Scoring helpers (identical logic to previous module)
# ──────────────────────────────────────────────────────────────────────────
def _count_by_severity(vulns: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"ERROR": 0, "WARNING": 0, "INFO": 0}
    for v in vulns:
        sev = v.get("extra", {}).get("severity", "").upper()
        if sev in counts:
            counts[sev] += 1
    return counts


def _calculate_security_score(vulns: List[Dict[str, Any]]) -> int:
    counts = _count_by_severity(vulns)
    score = 10.0 - (
        counts["ERROR"] * 2.0 + counts["WARNING"] * 1.0 + counts["INFO"] * 0.4
    )
    return max(1, int(round(score)))


# ──────────────────────────────────────────────────────────────────────────
#  Very small regex fallback if ChatGPT returns nothing
# ──────────────────────────────────────────────────────────────────────────
def _pattern_fallback(files: Dict[str, str]) -> List[Dict[str, Any]]:
    patterns = [
        ("exec(", "Command execution", "ERROR", 8),
        ("eval(", "Arbitrary code execution", "ERROR", 9),
        ("password =", "Hard-coded credential", "WARNING", 6),
        ("SELECT * FROM", "Possible SQL injection", "WARNING", 5),
        ("innerHTML", "Potential XSS", "WARNING", 6),
        ("http://", "Unencrypted HTTP", "INFO", 3),
        ("admin", "Privileged term", "INFO", 2),
    ]
    vulns: List[Dict[str, Any]] = []
    for path, content in list(files.items())[:3]:  # sample few files
        for idx, line in enumerate(content.splitlines(), 1):
            for pat, msg, sev, sc in patterns:
                if pat in line:
                    vulns.append(
                        {
                            "check_id": f"ai.security.{pat.strip('(').strip()}",  # simple slug
                            "path": path,
                            "start": {"line": idx, "col": 1},
                            "end": {"line": idx + 1, "col": 1},
                            "extra": {
                                "severity": sev,
                                "metadata": {"category": "Security", "score": sc},
                                "message": f"{msg}: {line.strip()}",
                                "lines": line.strip(),
                                "score": sc,
                            },
                            "severity": sev.lower(),
                        }
                    )
    return vulns
