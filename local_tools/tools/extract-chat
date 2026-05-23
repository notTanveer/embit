#!/usr/bin/env python3
"""Extract human-readable chat from Claude Code JSONL transcripts.

Usage:
  extract-chat <session.jsonl>                    # print to stdout
  extract-chat <session.jsonl> -o chat.txt        # write to file
  extract-chat <session.jsonl> | ask-kimi ...     # pipe to kimi

Extracts only user and assistant TEXT messages. Strips:
  - Tool calls, tool results, system prompts
  - Thinking blocks, signatures, binary data
  - Hooks, permissions, file snapshots, queue ops
"""
import argparse
import json


def extract(jsonl_path):
    messages = []
    with open(jsonl_path) as f:
        for line in f:
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue

            msg_type = msg.get("type")
            if msg_type not in ("user", "assistant"):
                continue

            inner = msg.get("message", {})
            role = inner.get("role", msg_type)
            content = inner.get("content", "")
            timestamp = msg.get("timestamp", "")

            texts = []
            if isinstance(content, str):
                content = content.strip()
                if content:
                    texts.append(content)
            elif isinstance(content, list):
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    if block.get("type") == "text":
                        t = block.get("text", "").strip()
                        if t:
                            texts.append(t)

            if texts:
                ts_tag = f" ({timestamp})" if timestamp else ""
                combined = "\n".join(texts)
                messages.append(f"[{role.upper()}]{ts_tag}:\n{combined}")

    return "\n\n---\n\n".join(messages)


def main():
    parser = argparse.ArgumentParser(description="Extract chat from Claude Code JSONL")
    parser.add_argument("jsonl", help="Path to .jsonl transcript")
    parser.add_argument("-o", "--output", help="Output file (default: stdout)")
    args = parser.parse_args()

    result = extract(args.jsonl)

    if args.output:
        with open(args.output, "w") as f:
            f.write(result)
        chars = len(result)
        lines = result.count("\n") + 1
        print(f"Wrote {lines} lines ({chars} chars) to {args.output}")
    else:
        print(result)


if __name__ == "__main__":
    main()
