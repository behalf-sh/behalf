#!/usr/bin/env python3
"""Assemble the browser verifier from the wasm artifacts and index.html.

Produces two things under --out-dir (both gitignored build outputs):

  index.html + behalf_verify.js + behalf_verify_bg.wasm + samples/
      the served build. Open over http://; the page fetches the local .wasm
      and the local sample and nothing else.

  verify.html
      the single-file build. The wasm-bindgen glue, the wasm module and the
      sample export are inlined, so the page opens straight from file:// with
      no server and makes no requests at all.

Splice points in index.html are HTML comments (BEHALF:GLUE, BEHALF:DATA,
BEHALF:STAMP); this script only ever substitutes between them, so the template
stays a readable, editable page.

Deliberately stdlib-only and dependency-free: the browser verifier's whole
claim is that it needs nothing, and its build should not need an npm tree to
say so.
"""

import argparse
import base64
import html
import pathlib
import shutil
import sys

GLUE_BEGIN = "<!--BEHALF:GLUE:BEGIN-->"
GLUE_END = "<!--BEHALF:GLUE:END-->"
DATA_BEGIN = "<!--BEHALF:DATA:BEGIN-->"
DATA_END = "<!--BEHALF:DATA:END-->"
STAMP = "<!--BEHALF:STAMP-->"


def splice(doc: str, begin: str, end: str, replacement: str, what: str) -> str:
    i = doc.find(begin)
    j = doc.find(end)
    if i < 0 or j < 0 or j < i:
        sys.exit(f"build.py: template is missing the {what} markers")
    return doc[:i] + replacement + doc[j + len(end):]


def close_script_safe(text: str) -> str:
    """Make text safe to embed inside a <script> element.

    Inside a classic script the only sequence that can end the element early
    is a literal `</script`; `<!--` also starts an HTML comment in the legacy
    script grammar. Neither can occur in base64, but the wasm-bindgen glue is
    real JavaScript, so escape both rather than assume.
    """
    return text.replace("</script", "<\\/script").replace("<!--", "<\\!--")


# Every HTML construct that can pull in a subresource. The single-file build
# must contain none of them: the page's central claim is that it fetches
# nothing, and a claim like that belongs in the build, not in a comment.
EXTERNAL_TAGS = ("<link", "<img", "<iframe", "<object", "<embed", "<source",
                 "<track", "<video", "<audio", "<base", "<applet", "<frame")


def assert_self_contained(doc: str, path: pathlib.Path) -> None:
    lowered = doc.lower()
    bad = [t for t in EXTERNAL_TAGS if t in lowered]
    if "<script src" in lowered:
        bad.append("<script src>")

    # CSS can fetch too, but only look inside <style> — `url(` also appears as
    # `new URL(` in the wasm-bindgen glue, which fetches nothing.
    i, j = lowered.find("<style"), lowered.rfind("</style>")
    if i >= 0 and j > i:
        css = lowered[i:j]
        bad += [c for c in ("@import", "url(") if c in css]

    # And the page must be configured to inline rather than fetch.
    for field in ("wasmurl", "sampleurl"):
        marker = field + ": null"
        if marker not in lowered:
            bad.append(f"{field} is not null")

    if bad:
        sys.exit(f"build.py: {path} is not self-contained — found {', '.join(sorted(set(bad)))}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--template", required=True, type=pathlib.Path)
    ap.add_argument("--glue", required=True, type=pathlib.Path,
                    help="wasm-bindgen --target no-modules JS shim")
    ap.add_argument("--wasm", required=True, type=pathlib.Path)
    ap.add_argument("--sample", type=pathlib.Path,
                    help="intact export to offer as the demo (optional)")
    ap.add_argument("--out-dir", required=True, type=pathlib.Path)
    ap.add_argument("--version", default="", help="crate version, for the footer stamp")
    args = ap.parse_args()

    for p in (args.template, args.glue, args.wasm):
        if not p.is_file():
            sys.exit(f"build.py: missing input {p}")

    out = args.out_dir
    out.mkdir(parents=True, exist_ok=True)

    template = args.template.read_text(encoding="utf-8")
    glue = args.glue.read_text(encoding="utf-8")
    wasm = args.wasm.read_bytes()

    sample_bytes = None
    sample_name = "run_c71e.jsonl"
    if args.sample and args.sample.is_file():
        sample_bytes = args.sample.read_bytes()
        sample_name = args.sample.name

    stamp_bits = [f"behalf-verify {args.version}".strip(),
                  "WebAssembly build, file mode only",
                  f"wasm {len(wasm):,} bytes"]
    stamp = html.escape(" — ".join(b for b in stamp_bits if b) + ".")

    # ---- served build -------------------------------------------------
    served = template.replace(STAMP, stamp)
    served = splice(
        served, DATA_BEGIN, DATA_END,
        "<script>\nwindow.BEHALF_BUILD = {\n"
        '  wasmB64: null,\n'
        '  wasmUrl: "./behalf_verify_bg.wasm",\n'
        '  sampleB64: null,\n'
        f'  sampleUrl: {"null" if sample_bytes is None else chr(34) + "./samples/" + sample_name + chr(34)},\n'
        f'  sampleName: "{sample_name}"\n'
        "};\n</script>",
        "BEHALF:DATA")
    (out / "index.html").write_text(served, encoding="utf-8")
    # wasm-bindgen usually writes straight into --out-dir, in which case these
    # are already in place.
    for src in (args.glue, args.wasm):
        dst = out / src.name
        if src.resolve() != dst.resolve():
            shutil.copyfile(src, dst)
    if sample_bytes is not None:
        (out / "samples").mkdir(exist_ok=True)
        (out / "samples" / sample_name).write_bytes(sample_bytes)

    # ---- single-file build --------------------------------------------
    single = template.replace(STAMP, stamp)
    single = splice(single, GLUE_BEGIN, GLUE_END,
                    "<script>\n" + close_script_safe(glue) + "\n</script>",
                    "BEHALF:GLUE")
    wasm_b64 = base64.b64encode(wasm).decode("ascii")
    sample_field = "null"
    if sample_bytes is not None:
        sample_field = '"' + base64.b64encode(sample_bytes).decode("ascii") + '"'
    single = splice(
        single, DATA_BEGIN, DATA_END,
        "<script>\nwindow.BEHALF_BUILD = {\n"
        f'  wasmB64: "{wasm_b64}",\n'
        "  wasmUrl: null,\n"
        f"  sampleB64: {sample_field},\n"
        "  sampleUrl: null,\n"
        f'  sampleName: "{sample_name}"\n'
        "};\n</script>",
        "BEHALF:DATA")
    single_path = out / "verify.html"
    assert_self_contained(single, single_path)
    single_path.write_text(single, encoding="utf-8")

    single_size = single_path.stat().st_size
    print(f"web: {out}/index.html  (served build; fetches ./{args.wasm.name})")
    print(f"web: {out}/verify.html ({single_size:,} bytes, self-contained, opens from file://)")
    if sample_bytes is None:
        print("web: no sample export bundled — run `make fixtures` first "
              "for the one-click tamper demo", file=sys.stderr)


if __name__ == "__main__":
    main()
