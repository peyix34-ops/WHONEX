
# WHONEX

WHONEX is a local-first file security analysis engine.

## Version

0.1.0

## Current capabilities

- UTF-8 text file analysis
- SHA-256 file fingerprinting
- File size restrictions
- Basic security rule detection
- Structured security findings
- JSON report generation
- Local processing without network uploads
- Optional report file creation

## Current detection rules

- Possible hardcoded credentials
- Dynamic code evaluation
- Potential unsafe shell execution
- Potentially unsafe Python pickle deserialization
- Potential unsafe innerHTML assignment

## Important limitations

This version is an initial heuristic scanner.

It does not prove that a detected issue is exploitable.
It does not support APK, PDF, archive, binary or directory analysis yet.
It does not perform penetration testing.
It is not a replacement for a professional security audit.

## Build

    cargo build --release

## Test

    cargo test

## Show information

    cargo run -- info

## Scan a text file

    cargo run -- scan ./sample.py

## Save a JSON report

    cargo run -- scan ./sample.py --output ./whonex-report.json

## Change maximum file size

    cargo run -- scan ./sample.py --max-file-mb 10

The default maximum file size is 20 MB.

## Privacy

WHONEX does not upload source files.
Analysis is performed locally.
A JSON report is created only when the user explicitly requests it.

The operating system and build environment may retain their own files or logs.

## Authorization

Only analyze files that you own or are explicitly authorized to assess.
