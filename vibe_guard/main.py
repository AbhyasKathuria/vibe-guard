import argparse
import asyncio
import json
import os
import sys
import uuid

from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

# Add parent directory to path so we can import vibe_guard
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Reconfigure stdout/stderr to support emojis and UTF-8 on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")  # type: ignore

from vibe_guard.agent import root_agent


async def run_scan_interactive(file_path: str, code_content: str | None = None):
    # Setup session and runner
    session_service = InMemorySessionService()
    session_id = str(uuid.uuid4())
    user_id = "local_dev_user"

    await session_service.create_session(
        app_name="vibe_guard", user_id=user_id, session_id=session_id
    )
    runner = Runner(
        agent=root_agent, app_name="vibe_guard", session_service=session_service
    )

    # Format the ScanInput payload as JSON
    scan_input_payload = {
        "file_path": file_path,
    }
    if code_content is not None:
        scan_input_payload["code_content"] = code_content

    # Initialize message
    new_message = types.Content(
        role="user", parts=[types.Part.from_text(text=json.dumps(scan_input_payload))]
    )

    print(
        f"[*] Starting security scan for '{file_path}' (Session ID: {session_id})...",
        flush=True,
    )

    while True:
        paused_interrupt_id = None
        paused_message = None
        paused_payload = None

        # Run the workflow
        async for event in runner.run_async(
            user_id=user_id, session_id=session_id, new_message=new_message
        ):
            # Print output content if any
            if event.content and event.content.parts:
                for part in event.content.parts:
                    if part.text:
                        print(part.text, end="", flush=True)
                    # Check if this is a RequestInput (HITL pause)
                    if (
                        part.function_call
                        and part.function_call.name == "adk_request_input"
                    ):
                        paused_interrupt_id = part.function_call.id
                        args = part.function_call.args or {}
                        paused_message = args.get(
                            "message", "Request for manager approval."
                        )
                        paused_payload = args.get("payload", {})

            # Print final outputs or logs
            if event.output and not event.partial:
                output = event.output
                if isinstance(output, dict) and "report" in output:
                    print("\n\n=== FINAL MARKDOWN REPORT ===")
                    print(output["report"])
                    print("=============================")
                    print(f"Status: {output.get('status', 'safe')}")
                    print(
                        f"Approved by Human: {output.get('approved_by_human', False)}"
                    )

        if paused_interrupt_id:
            print("\n" + "=" * 50)
            print(f"[!] WORKFLOW PAUSED: {paused_message}")
            if paused_payload and "report" in paused_payload:
                print("\n--- PREVIEW REPORT ---")
                print(paused_payload["report"])
                print("----------------------\n")
            print("=" * 50)

            # Interactive prompt
            try:
                choice = input("Enter decision (approve/reject): ").strip().lower()
                while choice not in ("approve", "reject"):
                    choice = (
                        input("Please enter 'approve' or 'reject': ").strip().lower()
                    )
            except (KeyboardInterrupt, EOFError):
                print("\n[!] Exiting scan execution. Session state remains suspended.")
                break

            # Create the resume response
            new_message = types.Content(
                role="user",
                parts=[
                    types.Part(
                        function_response=types.FunctionResponse(
                            id=paused_interrupt_id,
                            name="adk_request_input",
                            response={"decision": choice},
                        )
                    )
                ],
            )
            print(f"[*] Resuming session with decision: '{choice}'...", flush=True)
        else:
            # Not paused, workflow has finished
            break


def main():
    parser = argparse.ArgumentParser(
        description="Vibe-Guard Code Security Review Runner"
    )
    parser.add_argument("--file", required=True, help="Path to the file to scan")
    parser.add_argument(
        "--code",
        help="Optional code content to scan (scanned instead of reading the file)",
    )
    args = parser.parse_args()

    asyncio.run(run_scan_interactive(args.file, args.code))


if __name__ == "__main__":
    main()
