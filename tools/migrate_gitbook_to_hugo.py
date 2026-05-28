from __future__ import annotations

import html
import re
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "tmp" / "CTF_Writeups_Hugo"
CONTENT = ROOT / "content"
STATIC = ROOT / "static"


SUMMARY_RE = re.compile(r"^(?P<indent>\s*)\* \[(?P<title>.+?)\]\((?P<path>[^)]+)\)")
ASSET_REF_RE = re.compile(r"(?<!/)(?P<prefix>(?:\.\./)*)(?:\.gitbook/assets|challenge_files)/(?P<name>[^)\]\"'<>]+)")
FILE_RE = re.compile(r"\{%\s*file\s+src=\"(?P<src>[^\"]+)\"\s*%\}")
EMBED_RE = re.compile(r"\{%\s*embed\s+url=\"(?P<url>[^\"]+)\"\s*%\}")
TAB_RE = re.compile(r"\{%\s*tab\s+title=\"(?P<title>[^\"]*)\"\s*%\}")
CODE_OPEN_RE = re.compile(r"\{%\s*code(?:\s+[^%]*)?%\}")
HINT_OPEN_RE = re.compile(r"\{%\s*hint\s+style=\"(?P<style>[^\"]+)\"\s*%\}")


def yaml_quote(value: str) -> str:
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def extract_summary() -> dict[str, tuple[str, int]]:
    entries: dict[str, tuple[str, int]] = {}
    summary = SRC / "SUMMARY.md"
    if not summary.exists():
        return entries
    weight = 10
    for line in summary.read_text(encoding="utf-8").splitlines():
        match = SUMMARY_RE.match(line)
        if not match:
            continue
        path = match.group("path").replace("\\", "/")
        title = match.group("title")
        entries[path] = (title, weight)
        weight += 10
    return entries


def first_heading(text: str, fallback: str) -> str:
    for line in text.splitlines():
        match = re.match(r"^#\s+(.+?)\s*$", line)
        if match:
            return match.group(1)
    return fallback


def infer_date(rel: Path) -> str:
    parts = rel.parts
    for part in parts:
        if re.fullmatch(r"20\d{2}", part):
            return f"{part}-01-01T00:00:00+08:00"
    return "2022-01-01T00:00:00+08:00"


def infer_taxonomy(rel: Path) -> tuple[list[str], list[str], list[str]]:
    parts = list(rel.with_suffix("").parts)
    categories: list[str] = []
    tags: list[str] = []
    series: list[str] = []
    if parts and re.fullmatch(r"20\d{2}", parts[0]):
        categories.append(parts[0])
        if len(parts) > 1:
            series.append(parts[1].replace("-", " ").title())
        if len(parts) > 2 and parts[-1].lower() != "readme":
            tags.append(parts[-2].replace("-", " ").title())
    elif parts and parts[0] == "authored":
        categories.append("Authored")
        if len(parts) > 1:
            series.append(parts[1].replace("-", " ").title())
        if len(parts) > 2 and parts[-1].lower() != "readme":
            tags.append(parts[-2].replace("-", " ").title())
    return categories, tags, series


def list_yaml(values: list[str]) -> str:
    return "[" + ", ".join(yaml_quote(value) for value in values) + "]"


def rewrite_asset_path(value: str) -> str:
    value = value.strip()
    normalized = value.replace("\\", "/")
    if ".gitbook/assets/" in normalized:
        return "/gitbook/assets/" + normalized.split(".gitbook/assets/", 1)[1]
    if "challenge_files/" in normalized:
        return "/challenge_files/" + normalized.split("challenge_files/", 1)[1]
    return normalized


def transform_body(text: str) -> str:
    text = FILE_RE.sub(lambda m: f"[Download {Path(m.group('src')).name}]({rewrite_asset_path(m.group('src'))})", text)
    text = EMBED_RE.sub(lambda m: f"[{m.group('url')}]({m.group('url')})", text)
    text = re.sub(r"\{%\s*tabs\s*%\}", "{{< tabs >}}", text)
    text = re.sub(r"\{%\s*endtabs\s*%\}", "{{< /tabs >}}", text)
    text = TAB_RE.sub(lambda m: '{{< tab label=' + yaml_quote(m.group('title')) + ' >}}', text)
    text = re.sub(r"\{%\s*endtab\s*%\}", "{{< /tab >}}", text)
    text = CODE_OPEN_RE.sub("", text)
    text = re.sub(r"\{%\s*endcode\s*%\}", "", text)
    text = HINT_OPEN_RE.sub(lambda m: f"> **{m.group('style').upper()}**\n>", text)
    text = re.sub(r"\{%\s*endhint\s*%\}", "", text)
    text = re.sub(r"\{%\s*stepper\s*%\}", "", text)
    text = re.sub(r"\{%\s*endstepper\s*%\}", "", text)
    text = re.sub(r"\{%\s*step\s*%\}", "- ", text)
    text = re.sub(r"\{%\s*endstep\s*%\}", "", text)
    text = ASSET_REF_RE.sub(lambda m: ("/gitbook/assets/" if ".gitbook" in m.group(0) else "/challenge_files/") + m.group("name"), text)
    return text


def front_matter(src_rel: Path, body: str, summary: dict[str, tuple[str, int]], is_section: bool) -> str:
    key = src_rel.as_posix()
    fallback = src_rel.parent.name.replace("-", " ").title() if src_rel.name.lower() == "readme.md" else src_rel.stem.replace("-", " ").title()
    title, weight = summary.get(key, (first_heading(body, fallback), 999))
    categories, tags, series = infer_taxonomy(src_rel)
    params = ["---", f"title: {yaml_quote(title)}", "draft: false", f"weight: {weight}"]
    if not is_section:
        params.append(f"date: {infer_date(src_rel)}")
    if categories:
        params.append(f"categories: {list_yaml(categories)}")
    if tags:
        params.append(f"tags: {list_yaml(tags)}")
    if series:
        params.append(f"series: {list_yaml(series)}")
    params.append("---")
    return "\n".join(params) + "\n\n"


def destination_for(src_path: Path) -> tuple[Path, bool]:
    rel = src_path.relative_to(SRC)
    if rel.as_posix() == "README.md":
        return CONTENT / "_index.md", True
    if rel.name.lower() == "readme.md":
        return CONTENT / "posts" / rel.parent / "_index.md", True
    return CONTENT / "posts" / rel, False


def migrate_content() -> None:
    summary = extract_summary()
    if CONTENT.exists():
        shutil.rmtree(CONTENT)
    CONTENT.mkdir(parents=True, exist_ok=True)
    for src_path in sorted(SRC.rglob("*.md")):
        rel = src_path.relative_to(SRC)
        if rel.as_posix() == "SUMMARY.md" or rel.parts[0] in {"challenge_files", ".gitbook"}:
            continue
        body = src_path.read_text(encoding="utf-8")
        transformed = transform_body(body)
        dst_path, is_section = destination_for(src_path)
        dst_path.parent.mkdir(parents=True, exist_ok=True)
        dst_path.write_text(front_matter(rel, body, summary, is_section) + transformed, encoding="utf-8")


def copy_static() -> None:
    assets_src = SRC / ".gitbook" / "assets"
    assets_dst = STATIC / "gitbook" / "assets"
    challenge_src = SRC / "challenge_files"
    challenge_dst = STATIC / "challenge_files"
    if assets_dst.exists():
        shutil.rmtree(assets_dst)
    if challenge_dst.exists():
        shutil.rmtree(challenge_dst)
    if assets_src.exists():
        shutil.copytree(assets_src, assets_dst)
    if challenge_src.exists():
        shutil.copytree(challenge_src, challenge_dst)
    (STATIC / "CNAME").write_text("ctf.jonghan.xyz\n", encoding="utf-8")


def main() -> None:
    if not SRC.exists():
        raise SystemExit(f"Source directory not found: {SRC}")
    migrate_content()
    copy_static()


if __name__ == "__main__":
    main()
