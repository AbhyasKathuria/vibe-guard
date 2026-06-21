# ruff: noqa: E402
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import os
import subprocess
import tempfile
from typing import Literal

import dotenv

google_auth = None
try:
    import google.auth
except ImportError:
    pass

# Load environment variables from .env if present
dotenv.load_dotenv()

# Setup Vertex AI / GenAI environment variables
if os.environ.get("GOOGLE_API_KEY"):
    os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "False"
else:
    if not os.environ.get("GOOGLE_CLOUD_PROJECT") and google_auth:
        try:
            _, project_id = google.auth.default()
            if project_id:
                os.environ["GOOGLE_CLOUD_PROJECT"] = project_id
        except Exception:
            pass
    if not os.environ.get("GOOGLE_CLOUD_LOCATION"):
        os.environ["GOOGLE_CLOUD_LOCATION"] = "us-central1"
    os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "True"

from google.adk import Context, Event, Workflow
from google.adk.agents import LlmAgent
from google.adk.apps import App, ResumabilityConfig
from google.adk.events import EventActions, RequestInput
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Pydantic schemas for workflow data flow
# ---------------------------------------------------------------------------


class ScanInput(BaseModel):
    file_path: str = Field(description="Path to the file to scan")
    code_content: str | None = Field(
        default=None,
        description="Optional raw code content to scan (written to a temp file if provided)",
    )


class RawFinding(BaseModel):
    rule_id: str = Field(description="The Semgrep rule ID of the finding")
    file_path: str = Field(description="Path of the file containing the finding")
    line_number: int = Field(description="Line number of the finding")
    message: str = Field(description="Details/message of the finding")
    code_snippet: str = Field(description="The exact code snippet matched")
    context: str = Field(description="Surrounding code lines to help the LLM review")


class ScannerOutput(BaseModel):
    findings: list[RawFinding] = Field(
        description="List of raw findings found by Semgrep"
    )


class ConfirmedIssue(BaseModel):
    rule_id: str = Field(description="The Semgrep rule ID of the issue")
    file_path: str = Field(description="The path of the file containing the issue")
    line_number: int = Field(description="Line number of the issue")
    code_snippet: str = Field(description="The code snippet containing the issue")
    severity: Literal["low", "medium", "high", "critical"] = Field(
        description="The severity level of the issue"
    )
    reasoning: str = Field(
        description="Detailed explanation of why this is a true positive and why this severity was assigned"
    )


class RiskJudgeOutput(BaseModel):
    confirmed_issues: list[ConfirmedIssue] = Field(
        description="List of confirmed true positive security issues"
    )


class ConcreteFix(BaseModel):
    rule_id: str = Field(description="The Semgrep rule ID of the issue")
    file_path: str = Field(description="The path of the file containing the issue")
    line_number: int = Field(description="Line number of the issue")
    explanation: str = Field(
        description="Brief explanation of how the fix secures the code"
    )
    suggested_fix: str = Field(description="The concrete suggested code fix or patch")


class FixSuggesterOutput(BaseModel):
    fixes: list[ConcreteFix] = Field(
        description="List of security code fixes corresponding to confirmed issues"
    )


# ---------------------------------------------------------------------------
# Helper function for getting surrounding code context
# ---------------------------------------------------------------------------


def get_code_context(file_path: str, line_number: int, context_lines: int = 5) -> str:
    """Reads the scanned file and returns surrounding lines of context for the LLM."""
    if not os.path.exists(file_path):
        return ""
    try:
        with open(file_path, encoding="utf-8") as f:
            lines = f.readlines()
        start = max(0, line_number - 1 - context_lines)
        end = min(len(lines), line_number + context_lines)
        context = []
        for idx in range(start, end):
            prefix = "--> " if idx == line_number - 1 else "    "
            context.append(f"{prefix}{idx + 1}: {lines[idx]}")
        return "".join(context)
    except Exception as e:
        return f"Error reading context: {e}"


# ---------------------------------------------------------------------------
# Node 1: scanner_agent (Function Node)
# ---------------------------------------------------------------------------

import re


def simulate_semgrep_scan(
    file_path: str, code_content: str | None = None
) -> list[dict]:
    """Simulates Semgrep scan results on Windows when native CLI is unavailable."""
    content = ""
    if code_content is not None:
        content = code_content
    elif os.path.exists(file_path):
        try:
            with open(file_path, encoding="utf-8") as f:
                content = f.read()
        except Exception:
            pass

    findings = []
    if not content:
        return findings

    lines = content.splitlines()

    # 1. Custom hardcoded API key check
    api_key_pattern = re.compile(
        r'(?i)\b(api_key|apikey|secret|password|private_key|token|auth_token|api_token)\b\s*=\s*["\']([a-zA-Z0-9_\-\.]{16,64})["\']'
    )

    # 2. Subprocess call with shell=True
    subprocess_pattern = re.compile(
        r"subprocess\.(run|Popen|call|check_output|check_call)\(.*shell\s*=\s*True.*\)"
    )

    # 3. MD5 usage check (medium severity)
    md5_pattern = re.compile(r"hashlib\.md5\(.*\)")

    # 4. Insecure random usage check (low severity)
    random_pattern = re.compile(r"\brandom\.(random|randint|choice|randrange)\(.*\)")

    for idx, line in enumerate(lines):
        line_num = idx + 1

        # Check API key
        match_key = api_key_pattern.search(line)
        if match_key:
            context = []
            start = max(0, idx - 5)
            end = min(len(lines), idx + 6)
            for c_idx in range(start, end):
                prefix = "--> " if c_idx == idx else "    "
                context.append(f"{prefix}{c_idx + 1}: {lines[c_idx]}")

            findings.append(
                {
                    "check_id": "rules.hardcoded-api-key",
                    "path": file_path,
                    "start": {"line": line_num},
                    "extra": {
                        "message": "Potential hardcoded API key, token, or secret detected.",
                        "lines": line.strip(),
                        "severity": "WARNING",
                    },
                    "context": "\n".join(context),
                }
            )

        # Check subprocess
        match_sub = subprocess_pattern.search(line)
        if match_sub:
            context = []
            start = max(0, idx - 5)
            end = min(len(lines), idx + 6)
            for c_idx in range(start, end):
                prefix = "--> " if c_idx == idx else "    "
                context.append(f"{prefix}{c_idx + 1}: {lines[c_idx]}")

            findings.append(
                {
                    "check_id": "python.lang.security.audit.dangerous-subprocess-use-audit",
                    "path": file_path,
                    "start": {"line": line_num},
                    "extra": {
                        "message": "Found subprocess with shell=True. This can lead to command injection if user input is passed.",
                        "lines": line.strip(),
                        "severity": "ERROR",
                    },
                    "context": "\n".join(context),
                }
            )

        # Check MD5 (medium)
        match_md5 = md5_pattern.search(line)
        if match_md5:
            context = []
            start = max(0, idx - 5)
            end = min(len(lines), idx + 6)
            for c_idx in range(start, end):
                prefix = "--> " if c_idx == idx else "    "
                context.append(f"{prefix}{c_idx + 1}: {lines[c_idx]}")

            findings.append(
                {
                    "check_id": "python.lang.security.audit.insecure-hash-algorithms.insecure-hash-algorithm-md5",
                    "path": file_path,
                    "start": {"line": line_num},
                    "extra": {
                        "message": "Insecure hash algorithm MD5 used. Use SHA-256 or SHA-3 instead.",
                        "lines": line.strip(),
                        "severity": "WARNING",
                    },
                    "context": "\n".join(context),
                }
            )

        # Check random (low)
        match_random = random_pattern.search(line)
        if match_random:
            context = []
            start = max(0, idx - 5)
            end = min(len(lines), idx + 6)
            for c_idx in range(start, end):
                prefix = "--> " if c_idx == idx else "    "
                context.append(f"{prefix}{c_idx + 1}: {lines[c_idx]}")

            findings.append(
                {
                    "check_id": "python.lang.security.audit.crypto.bad-random.bad-random",
                    "path": file_path,
                    "start": {"line": line_num},
                    "extra": {
                        "message": "Standard pseudo-random number generator used. For security-sensitive applications, use the secrets module instead.",
                        "lines": line.strip(),
                        "severity": "INFO",
                    },
                    "context": "\n".join(context),
                }
            )

    return findings


def scanner_agent(node_input: ScanInput, ctx: Context) -> Event:
    """Runs Semgrep against the file path or code content, and extracts findings."""
    file_path = node_input.file_path
    code_content = node_input.code_content
    temp_file = None

    # Check if a real semgrep binary is available
    semgrep_available = False
    try:
        subprocess.run(
            ["semgrep", "--version"], capture_output=True, text=True, timeout=2
        )
        semgrep_available = True
    except (FileNotFoundError, subprocess.SubprocessError):
        try:
            res = subprocess.run(
                ["uv", "run", "semgrep", "--version"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            semgrep_available = res.returncode == 0
        except (FileNotFoundError, subprocess.SubprocessError):
            pass

    if not semgrep_available:
        print(
            "[*] Semgrep binary not found in PATH or virtual env. Using pattern-matching simulation.",
            flush=True,
        )
        results = simulate_semgrep_scan(file_path, code_content)
        findings = []
        for r in results:
            raw_finding = RawFinding(
                rule_id=r.get("check_id", "unknown-rule"),
                file_path=r.get("path"),
                line_number=r.get("start", {}).get("line", 1),
                message=r.get("extra", {}).get("message", "No description"),
                code_snippet=r.get("extra", {}).get("lines", ""),
                context=r.get("context", ""),
            )
            findings.append(raw_finding.model_dump())
        return Event(output={"findings": findings})

    try:
        if code_content is not None:
            suffix = os.path.splitext(file_path)[1] or ".py"
            fd, temp_path = tempfile.mkstemp(suffix=suffix, text=True)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(code_content)
            temp_file = temp_path
            scan_target = temp_path
        else:
            scan_target = file_path

        if not os.path.exists(scan_target):
            return Event(
                output={"findings": []},
                actions=EventActions(
                    state_delta={
                        "scanner_error": f"Target path {scan_target} does not exist"
                    }
                ),
            )

        # Get custom ruleset path
        custom_rules_path = os.path.join(os.path.dirname(__file__), "custom_rules.yaml")

        # Primary Semgrep execution command
        cmd = [
            "semgrep",
            "--config=p/security-audit",
            f"--config={custom_rules_path}",
            "--json",
            scan_target,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)

        try:
            data = json.loads(result.stdout)
            results = data.get("results", [])
        except Exception as e:
            # Fallback: Semgrep might fail because p/security-audit needs internet/auth; retry with only custom rules
            print(
                f"Semgrep registry connection issue, retrying with only custom rules: {e}",
                flush=True,
            )
            cmd_fallback = [
                "semgrep",
                f"--config={custom_rules_path}",
                "--json",
                scan_target,
            ]
            result_fallback = subprocess.run(
                cmd_fallback, capture_output=True, text=True, check=False
            )
            try:
                data = json.loads(result_fallback.stdout)
                results = data.get("results", [])
            except Exception as e2:
                # Last resort fallback: run via uv command
                print(f"Fallback semgrep failed, trying uv run: {e2}", flush=True)
                cmd_uv = [
                    "uv",
                    "run",
                    "semgrep",
                    f"--config={custom_rules_path}",
                    "--json",
                    scan_target,
                ]
                result_uv = subprocess.run(
                    cmd_uv, capture_output=True, text=True, check=False
                )
                try:
                    data = json.loads(result_uv.stdout)
                    results = data.get("results", [])
                except Exception as e3:
                    return Event(
                        output={"findings": []},
                        actions=EventActions(
                            state_delta={
                                "scanner_error": f"Failed to run semgrep: {e3}"
                            }
                        ),
                    )

        findings = []
        for r in results:
            finding_path = file_path if code_content is not None else r.get("path")
            line_no = r.get("start", {}).get("line", 1)

            raw_finding = RawFinding(
                rule_id=r.get("check_id", "unknown-rule"),
                file_path=finding_path,
                line_number=line_no,
                message=r.get("extra", {}).get("message", "No description"),
                code_snippet=r.get("extra", {}).get("lines", ""),
                context=get_code_context(scan_target, line_no),
            )
            findings.append(raw_finding.model_dump())

        return Event(output={"findings": findings})

    finally:
        if temp_file and os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Node 2: risk_judge_agent (LLM Agent Node)
# ---------------------------------------------------------------------------

risk_judge_agent = LlmAgent(
    name="risk_judge_agent",
    model="gemini-3.1-flash-lite",
    instruction="""You are a security risk judge. You receive a list of raw Semgrep findings from a code scan, including the code snippets and surrounding context.
Your tasks:
1. Review each finding and determine if it is a true positive or a false positive.
2. For each confirmed true positive issue, assign a severity score of: 'low', 'medium', 'high', or 'critical'.
   - 'critical': Remote code execution, hardcoded private keys or production credentials, SQL injection, severe auth bypass.
   - 'high': Common OWASP top ten issues, weak hashing, debug mode enabled in prod.
   - 'medium': Insecure configuration, path traversal risk, lack of rate limiting.
   - 'low': Code quality issues, minor style issues, deprecated functions with low impact.
3. Provide a clear reasoning/explanation for your decision.
4. Output only the confirmed issues in the structured schema. Filter out any false positives.""",
    output_schema=RiskJudgeOutput,
    output_key="risk_judge_output",
)


# ---------------------------------------------------------------------------
# Node 3: fix_suggester_agent (LLM Agent Node)
# ---------------------------------------------------------------------------

fix_suggester_agent = LlmAgent(
    name="fix_suggester_agent",
    model="gemini-3.1-flash-lite",
    instruction="""You are a security code fix suggester. You receive a list of confirmed security issues.
For each issue, generate:
1. A clear explanation of what is wrong and how to fix it.
2. A concrete suggested code fix or patch (e.g. secure coding pattern, usage of secret manager, parameterized queries).
Output only the structured list of fixes.""",
    output_schema=FixSuggesterOutput,
    output_key="fix_suggester_output",
)


# ---------------------------------------------------------------------------
# Node 4: reporter_agent (Function Node)
# ---------------------------------------------------------------------------


def get_val(obj, key, default=None):
    """Helper to dynamically get values from either dicts or object attributes."""
    if hasattr(obj, key):
        return getattr(obj, key)
    if isinstance(obj, dict):
        return obj.get(key, default)
    return default


def generate_report_markdown(issues: list, fixes: list) -> str:
    """Formats findings and fixes into a clean, GitHub PR comment-compatible report."""
    if not issues:
        return "# Vibe-Guard Security Review Report\n\nNo security issues were detected. Your code looks clean! ✅"

    report = "# Vibe-Guard Security Review Report\n\n"
    report += f"We found {len(issues)} security issues in your code.\n\n"

    report += "## Summary of Findings\n"
    report += "| # | File | Line | Rule | Severity |\n"
    report += "|---|------|------|------|----------|\n"
    for i, issue in enumerate(issues):
        severity = get_val(issue, "severity", "low")
        sev_icon = {
            "critical": "🔴 CRITICAL",
            "high": "orange_circle HIGH",
            "medium": "yellow_circle MEDIUM",
            "low": "blue_circle LOW",
        }.get(severity.lower(), severity)
        # Replace names for visual representation
        sev_icon = (
            sev_icon.replace("orange_circle", "🟠")
            .replace("yellow_circle", "🟡")
            .replace("blue_circle", "🔵")
        )
        report += f"| {i + 1} | `{get_val(issue, 'file_path')}` | {get_val(issue, 'line_number')} | `{get_val(issue, 'rule_id')}` | {sev_icon} |\n"
    report += "\n"

    report += "## Detailed Issues and Fixes\n"
    fix_map = {}
    for fix in fixes:
        key = f"{get_val(fix, 'rule_id')}:{get_val(fix, 'file_path')}:{get_val(fix, 'line_number')}"
        fix_map[key] = fix

    for i, issue in enumerate(issues):
        severity = get_val(issue, "severity", "low")
        sev_icon = {
            "critical": "🔴 CRITICAL",
            "high": "🟠 HIGH",
            "medium": "🟡 MEDIUM",
            "low": "🔵 LOW",
        }.get(severity.lower(), severity)

        report += f"### {i + 1}. [{sev_icon}] Rule: `{get_val(issue, 'rule_id')}`\n"
        report += f"- **File**: `{get_val(issue, 'file_path')}` (Line {get_val(issue, 'line_number')})\n"
        report += f"- **Reasoning**: {get_val(issue, 'reasoning')}\n"
        report += (
            f"- **Code Snippet**:\n```python\n{get_val(issue, 'code_snippet')}\n```\n"
        )

        key = f"{get_val(issue, 'rule_id')}:{get_val(issue, 'file_path')}:{get_val(issue, 'line_number')}"
        fix = fix_map.get(key)
        if fix:
            report += f"- **Explanation**: {get_val(fix, 'explanation')}\n"
            report += f"- **Suggested Fix**:\n```python\n{get_val(fix, 'suggested_fix')}\n```\n"
        else:
            report += "- **Suggested Fix**: None provided.\n"
        report += "\n"

    return report


def reporter_agent(node_input: FixSuggesterOutput, ctx: Context) -> Event:
    """Formats markdown report and handles conditional routing if any critical issues exist."""
    # Retrieve risk judge output from context state
    judge_state = ctx.state.get("risk_judge_output", {})
    confirmed_issues = judge_state.get("confirmed_issues", [])

    # Retrieve fixes from node_input or context state
    fixes = (
        node_input.fixes
        if hasattr(node_input, "fixes")
        else node_input.get("fixes", [])
    )

    # Check if there are any critical findings
    has_critical = any(
        issue.get("severity") == "critical" for issue in confirmed_issues
    )

    # Generate the Markdown report
    report = generate_report_markdown(confirmed_issues, fixes)
    ctx.state["markdown_report"] = report

    if has_critical:
        # Route to approval gate
        return Event(
            output={"report": report},
            actions=EventActions(route="NEEDS_APPROVAL"),
        )
    else:
        # Route directly to safe
        return Event(
            output={"report": report, "safe": True},
            actions=EventActions(route="SAFE"),
        )


# ---------------------------------------------------------------------------
# Node 5: finish_safe (Function Node)
# ---------------------------------------------------------------------------


def finish_safe(node_input: dict) -> Event:
    """Finalizes safe run report when no critical issues exist."""
    report = node_input.get("report", "")
    return Event(
        output={"report": report, "status": "safe", "approved_by_human": False}
    )


# ---------------------------------------------------------------------------
# Node 6: request_approval (Function Node - yields RequestInput)
# ---------------------------------------------------------------------------


def request_approval(node_input: dict, ctx: Context):
    """Pauses workflow for manager approval when critical findings are present."""
    yield RequestInput(
        interrupt_id="critical_approval",
        message="Vibe-Guard: A CRITICAL security issue was detected. Manager approval required to mark PR as safe.",
        payload={"report": node_input.get("report")},
    )


# ---------------------------------------------------------------------------
# Node 7: process_decision (Function Node)
# ---------------------------------------------------------------------------


def process_decision(node_input, ctx: Context) -> Event:
    """Processes manager's decision on the critical findings and appends status to the report."""
    decision = "unknown"
    if isinstance(node_input, dict):
        decision = node_input.get("decision", "unknown")
    elif isinstance(node_input, str):
        decision = "approve" if "approve" in node_input.lower() else "reject"

    approved = decision == "approve"
    report = ctx.state.get("markdown_report", "")

    status_suffix = "\n\n---\n### 👤 Human Approval Status\n"
    if approved:
        status_suffix += "✅ **APPROVED** (PR marked safe despite critical issues)"
        status = "safe"
    else:
        status_suffix += "❌ **REJECTED** (PR blocked due to critical issues)"
        status = "unsafe"

    final_report = report + status_suffix
    return Event(
        output={"report": final_report, "status": status, "approved_by_human": approved}
    )


# ---------------------------------------------------------------------------
# Workflow orchestration
# ---------------------------------------------------------------------------

root_agent = Workflow(
    name="vibe_guard_workflow",
    edges=[
        ("START", scanner_agent),
        (scanner_agent, risk_judge_agent),
        (risk_judge_agent, fix_suggester_agent),
        (fix_suggester_agent, reporter_agent),
        (
            reporter_agent,
            {
                "SAFE": finish_safe,
                "NEEDS_APPROVAL": request_approval,
            },
        ),
        (request_approval, process_decision),
    ],
    input_schema=ScanInput,
)

# App instance
app = App(
    root_agent=root_agent,
    name="vibe_guard",
    resumability_config=ResumabilityConfig(is_resumable=True),
)
