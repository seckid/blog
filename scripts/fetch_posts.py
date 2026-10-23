"""Write posts.json from the Medium RSS feed.

The blog is a static site. Browsers cannot read medium.com directly, and the
old rss2json proxy now returns 403. This script runs where the network is
allowed (locally, or in GitHub Actions) and saves the post list beside the site.
"""

from __future__ import annotations

import json
import re
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from html import unescape
from pathlib import Path

FEED_URL = "https://medium.com/feed/@seckid"
ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "posts.json"

CONTENT_NS = "http://purl.org/rss/1.0/modules/content/"
DC_NS = "http://purl.org/dc/elements/1.1/"
TAG_RE = re.compile(r"<[^>]+>")
IMG_RE = re.compile(r"""<img[^>]+src=["']([^"']+)["']""", re.I)
SPACE_RE = re.compile(r"\s+")


def _text(node: ET.Element | None) -> str:
    if node is None or node.text is None:
        return ""
    return unescape(node.text).strip()


def _strip(html: str) -> str:
    return SPACE_RE.sub(" ", TAG_RE.sub(" ", unescape(html or ""))).strip()


def _excerpt(html: str) -> str:
    text = _strip(html)
    if len(text) <= 200:
        return text
    return text[:200].rstrip() + "..."


def _image(html: str) -> str | None:
    match = IMG_RE.search(html or "")
    if not match:
        return None
    url = match.group(1)
    url = re.sub(r"[?&][wh]=\d+", "", url)
    url = url.rstrip("?&")
    joiner = "&" if "?" in url else "?"
    return url + joiner + "w=800"


def _date(value: str) -> str:
    try:
        parsed = parsedate_to_datetime(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.date().isoformat()
    except (TypeError, ValueError, IndexError):
        return datetime.now(timezone.utc).date().isoformat()


def _posts(xml_bytes: bytes) -> list[dict]:
    root = ET.fromstring(xml_bytes)
    posts = []
    for item in root.findall("./channel/item"):
        title = _text(item.find("title"))
        link = _text(item.find("link"))
        guid = _text(item.find("guid")) or link.rsplit("/", 1)[-1]
        content = _text(item.find(f"{{{CONTENT_NS}}}encoded"))
        description = _text(item.find("description"))
        categories = [_text(node) for node in item.findall("category")]
        categories = [name for name in categories if name]
        author = _text(item.find(f"{{{DC_NS}}}creator"))
        posts.append(
            {
                "id": guid,
                "title": title,
                "date": _date(_text(item.find("pubDate"))),
                "category": categories[0] if categories else "Article",
                "tags": categories[:3],
                "excerpt": _excerpt(description or content),
                "link": link,
                "author": author,
                "thumbnail": _image(content or description),
            }
        )
    posts.sort(key=lambda post: post["date"], reverse=True)
    return posts


def main() -> None:
    request = urllib.request.Request(
        FEED_URL,
        headers={"User-Agent": "securitykid-blog"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = response.read()
    posts = _posts(payload)
    OUT.write_text(json.dumps(posts, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(posts)} posts to {OUT.name}")


if __name__ == "__main__":
    main()
