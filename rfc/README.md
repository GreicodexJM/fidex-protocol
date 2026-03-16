# FideX AS5 Protocol — IETF Internet-Draft

This directory contains the IETF Internet-Draft for the FideX Protocol (AS5), formatted in
[RFCXML v3](https://authors.ietf.org/en/rfcxml-vocabulary) for processing with
[`xml2rfc`](https://xml2rfc.tools.ietf.org/).

## Documents

| File | Title | Status |
|------|-------|--------|
| `draft-greicodex-fidex-protocol-00.xml` | FideX Application Statement 5 (AS5) Protocol | I-D |

## Prerequisites

Install `xml2rfc` (Python-based tool):

```bash
pip install xml2rfc
# or
pip3 install xml2rfc
```

Install `xmllint` for schema validation:

```bash
# Debian/Ubuntu
sudo apt install libxml2-utils

# macOS
brew install libxml2
```

## Building

```bash
# Build all output formats (text + HTML)
make build

# Build only HTML
make html

# Build only plain text
make txt

# Validate XML well-formedness
make validate

# Clean generated files
make clean
```

## Output Files

After running `make build`, the following files are generated:

| File | Description |
|------|-------------|
| `draft-greicodex-fidex-protocol-00.txt` | Plain text (IETF canonical format) |
| `draft-greicodex-fidex-protocol-00.html` | HTML with navigation |
| `draft-greicodex-fidex-protocol-00.pdf` | PDF (requires `weasyprint` or `pdflatex`) |

## IETF Submission

To submit as an Internet-Draft:

1. Build and validate: `make build`
2. Submit at: https://datatracker.ietf.org/submit/
3. The `docName` in the XML must match the filename without `.xml`

## Document Naming Convention

IETF Internet-Drafts follow the pattern:

```
draft-{author/org}-{topic}-{version}.xml
```

- `greicodex` — Individual submitter organization
- `fidex-protocol` — The protocol name
- `00` — First revision (increment for each new submission)

## References

- [RFCXML Vocabulary](https://authors.ietf.org/en/rfcxml-vocabulary)
- [xml2rfc Documentation](https://xml2rfc.tools.ietf.org/)
- [IETF Internet-Draft Submission](https://datatracker.ietf.org/submit/)
- [RFC 7991 — RFCXML Format](https://www.rfc-editor.org/rfc/rfc7991)
- [FideX Normative Specification](../fidex-protocol-specification.md)
