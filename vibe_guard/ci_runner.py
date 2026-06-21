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

import asyncio
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Any

# Reconfigure stdout/stderr to support UTF-8 encoding
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")  # type: ignore

# Add parent directory to path so we can import vibe_guard
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

from vibe_guard.agent import root_agent

# Parse GitHub env vars
repo = os.environ.get("GITHUB_REPOSITORY")
event_path = os.environ.get("GITHUB_EVENT_PATH")
token = os.environ.get("GITHUB_TOKEN") or os.environ.get("INPUT_GITHUB_TOKEN")


def github_api_request(
    method: str, url: str, api_token: str, data: dict[str, Any] | None = None
) -> dict[str, Any] | None:
    """Helper function to make GitHub API requests using urllib."""
    req = urllib.request.Request(url, method=method)
    req.add_header("Authorization", f"token {api_token}")
    req.add_header("Accept", "application/vnd.github.v3+json")
    req.add_header("User-Agent", "vibe-guard-ci")

    body = None
    if data is not None:
        req.add_header("Content-Type", "application/json")
        body = json.dumps(data).encode("utf-8")

    try:
        with urllib.request.urlopen(req, data=body) as response:
            res_data = response.read()
            if res_data:
                return json.loads(res_data.decode("utf-8"))
            return {}
    except urllib.error.HTTPError as e:
        print(f"[!] GitHub API Error: {e.code} {e.reason}", flush=True)
        try:
            print(e.read().decode("utf-8"), flush=True)
        except Exception:
            pass
        raise
    except Exception as e:
        print(f"[!] Network Error: {e}", flush=True)
        raise


def set_commit_status(head_sha: str, state: str, description: str) -> None:
    """Updates the commit status check named vibe-guard on GitHub."""
    if not repo or not token:
        return
    url = f"https://api.github.com/repos/{repo}/statuses/{head_sha}"
    run_id = os.environ.get("GITHUB_RUN_ID")
    target_url = f"https://github.com/{repo}/actions/runs/{run_id}" if run_id else None

    payload = {
        "state": state,
        "description": description[:140],  # Description limit is 140 chars
        "context": "vibe-guard",
    }
    if target_url:
        payload["target_url"] = target_url

    try:
        github_api_request("POST", url, token, payload)
        print(f"[*] Set commit status check 'vibe-guard' to: {state}", flush=True)
    except Exception as e:
        print(f"[!] Failed to set commit status: {e}", flush=True)


def post_pr_comment(pr_num: int, body: str) -> None:
    """Posts a comment containing the markdown report to the pull request."""
    if not repo or not token:
        return
    url = f"https://api.github.com/repos/{repo}/issues/{pr_num}/comments"
    payload = {"body": body}
    try:
        github_api_request("POST", url, token, payload)
        print("[*] Posted review report as PR comment.", flush=True)
    except Exception as e:
        print(f"[!] Failed to post PR comment: {e}", flush=True)


async def scan_file(file_path: str) -> tuple[str, bool]:
    """Runs vibe-guard workflow on a file and returns its report and whether it triggered critical issues."""
    session_service = InMemorySessionService()
    session_id = f"ci_{file_path.replace('/', '_').replace('.', '_')}"
    user_id = "ci_runner"

    await session_service.create_session(
        app_name="vibe_guard", user_id=user_id, session_id=session_id
    )
    runner = Runner(
        agent=root_agent, app_name="vibe_guard", session_service=session_service
    )

    payload = {"file_path": file_path}
    new_message = types.Content(
        role="user",
        parts=[types.Part.from_text(text=json.dumps(payload))],
    )

    report = ""
    is_critical = False

    async for event in runner.run_async(
        user_id=user_id, session_id=session_id, new_message=new_message
    ):
        if event.content and event.content.parts:
            for part in event.content.parts:
                if (
                    part.function_call
                    and part.function_call.name == "adk_request_input"
                ):
                    is_critical = True
                    args = part.function_call.args or {}
                    paused_payload = args.get("payload", {})
                    report = paused_payload.get("report", "")

        if event.output and not event.partial:
            output = event.output
            if isinstance(output, dict) and "report" in output:
                report = output["report"]

    return report, is_critical


async def main() -> None:
    if not repo or not event_path or not token:
        print(
            "[!] GitHub Actions environment variables (GITHUB_REPOSITORY, GITHUB_EVENT_PATH, GITHUB_TOKEN) not set. Exiting.",
            flush=True,
        )
        sys.exit(1)

    if not os.path.exists(event_path):
        print(f"[!] Event path does not exist: {event_path}", flush=True)
        sys.exit(1)

    with open(event_path, encoding="utf-8") as f:
        event_data = json.load(f)

    pr_number = event_data.get("pull_request", {}).get("number")
    head_sha = event_data.get("pull_request", {}).get("head", {}).get("sha")
    base_ref = event_data.get("pull_request", {}).get("base", {}).get("ref")

    if not pr_number or not head_sha or not base_ref:
        print(
            "[!] Could not parse pull request number, head SHA, or base ref from GITHUB_EVENT_PATH. Exiting.",
            flush=True,
        )
        sys.exit(1)

    print(f"[*] Initializing Vibe-Guard scan for PR #{pr_number}...", flush=True)
    set_commit_status(head_sha, "pending", "Vibe-Guard is reviewing code changes...")

    # Fetch base branch to ensure we can diff against it
    try:
        subprocess.run(["git", "fetch", "origin", base_ref], check=True)
    except Exception as e:
        print(
            f"[*] Warning: git fetch origin {base_ref} failed: {e}. Trying diff anyway.",
            flush=True,
        )

    # Get modified and added files
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", f"origin/{base_ref}...HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
        changed_files = [
            line.strip() for line in result.stdout.splitlines() if line.strip()
        ]
    except Exception as e:
        print(f"[!] git diff failed: {e}", flush=True)
        set_commit_status(
            head_sha, "error", "Failed to retrieve modified files from Git diff."
        )
        sys.exit(1)

    # Filter files to scan
    files_to_scan = []
    for f_path in changed_files:
        if not os.path.isfile(f_path):
            continue
        basename = os.path.basename(f_path)
        # Skip lockfiles, configs, workflows, and ignored dirs
        if (
            ".git" in f_path
            or ".github" in f_path
            or "venv" in f_path
            or "node_modules" in f_path
            or basename
            in [
                "uv.lock",
                "pyproject.toml",
                "package-lock.json",
                "custom_rules.yaml",
                "ci_runner.py",
            ]
        ):
            continue
        files_to_scan.append(f_path)

    if not files_to_scan:
        print("[*] No code files modified in this PR. Skipping review.", flush=True)
        set_commit_status(head_sha, "success", "Vibe-Guard skipped (no code changes).")
        sys.exit(0)

    print(f"[*] Files to scan: {files_to_scan}", flush=True)

    combined_report = []
    combined_report.append("# 🛡️ Vibe-Guard Security Review Report\n")
    combined_report.append(
        f"We scanned **{len(files_to_scan)}** modified files in this Pull Request.\n"
    )

    any_critical = False

    for file_path in files_to_scan:
        combined_report.append(f"## 📄 File: `{file_path}`\n")
        try:
            report, is_critical = await scan_file(file_path)
            if is_critical:
                any_critical = True

            if report:
                combined_report.append(report)
            else:
                combined_report.append(
                    "No findings returned or error compiling report."
                )
        except Exception as e:
            print(f"[!] Error scanning {file_path}: {e}", flush=True)
            combined_report.append(f"❌ **Error scanning file**: {e}\n")
            any_critical = True  # Treat errors as failure

        combined_report.append("\n---\n")

    # Add final manual override guidance
    if any_critical:
        combined_report.append("\n## 🚨 Manual Override Instructions\n")
        combined_report.append(
            "A **critical** security issue was detected, blocking this pull request.\n\n"
        )
        combined_report.append(
            "An authorized repository collaborator can review the findings above and override this block by posting a comment on this PR with:\n"
        )
        combined_report.append("> `/vibe-guard approve`\n")
    else:
        combined_report.append(
            "\n✅ All scanned files passed the security check successfully.\n"
        )

    full_markdown = "\n".join(combined_report)

    # Post report comment to PR
    post_pr_comment(pr_number, full_markdown)

    # Set final commit status check and exit code
    if any_critical:
        set_commit_status(
            head_sha,
            "failure",
            "Vibe-Guard review failed. Critical issues found.",
        )
        sys.exit(1)
    else:
        set_commit_status(head_sha, "success", "Vibe-Guard review passed successfully.")
        sys.exit(0)


if __name__ == "__main__":
    asyncio.run(main())
