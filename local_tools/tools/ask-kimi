#!/usr/bin/env python3
"""Delegate bulk reading to Kimi K2.5. Returns a summary to Claude.

Kimi K2.5 is a thinking model — it uses reasoning tokens internally.
max-tokens must be high enough to cover both reasoning + answer.
"""
import argparse, os, sys, pathlib
from openai import OpenAI

client = OpenAI(
    api_key=os.environ.get("WORKER_API_KEY", os.environ.get("MOONSHOT_API_KEY", "")),
    base_url=os.environ.get("WORKER_BASE_URL", "https://api.moonshot.ai/v1"),
)

p = argparse.ArgumentParser(description="Ask Kimi to read and summarize files")
p.add_argument("--paths", nargs="+", required=True, help="Files to read")
p.add_argument("--question", required=True, help="What to extract/answer")
p.add_argument("--max-tokens", type=int, default=8192,
               help="Total token budget (reasoning + answer)")
p.add_argument("--model", default=os.environ.get("WORKER_MODEL", "kimi-k2.5"))
args = p.parse_args()

# Build a stable prefix for cache hits (book/corpus first, question last)
docs = []
for path in args.paths:
    content = pathlib.Path(path).read_text(errors="replace")
    docs.append(f"<file path='{path}'>\n{content}\n</file>")
corpus = "\n\n".join(docs)

resp = client.chat.completions.create(
    model=args.model,
    messages=[
        {"role": "system", "content": (
            "You are a precise code/document analyst. Read the provided files "
            "and answer the question concisely. Quote file paths and line "
            "numbers when relevant. Output structured bullets, not prose. "
            "Keep your answer under 800 words."
        )},
        {"role": "user", "content": f"<corpus>\n{corpus}\n</corpus>"},
        {"role": "user", "content": args.question},
    ],
    max_tokens=args.max_tokens,
)

answer = resp.choices[0].message.content
if answer:
    print(answer)
else:
    # Fallback: if content is empty but reasoning exists, model hit token limit
    print("[ERROR: Kimi ran out of tokens during reasoning. "
          "Try --max-tokens 16384]", file=sys.stderr)
    sys.exit(1)

# Cost report to stderr
u = resp.usage
cached = getattr(getattr(u, 'prompt_tokens_details', None), 'cached_tokens', 0) or 0
print(f"\n[kimi: {u.prompt_tokens} in ({cached} cached) / "
      f"{u.completion_tokens} out | finish: {resp.choices[0].finish_reason}]",
      file=sys.stderr)
