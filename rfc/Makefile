# FideX RFC Makefile
# Requires: xml2rfc (pip3 install xml2rfc)
#
# Usage:
#   make all       — build text + HTML from XML source
#   make text      — build .txt only
#   make html      — build .html only
#   make validate  — validate XML well-formedness with xmllint
#   make clean     — remove generated output files
#   make install   — install xml2rfc via pip3
#
DRAFT   = draft-greicodex-fidex-protocol-00
XML     = $(DRAFT).xml
TXT     = $(DRAFT).txt
HTML    = $(DRAFT).html

XML2RFC = xml2rfc
XMLLINT = xmllint

.PHONY: all text html validate clean install

all: validate text html
	@echo "✅ RFC build complete: $(TXT) + $(HTML)"

text: $(TXT)

$(TXT): $(XML)
	$(XML2RFC) $(XML) --text
	@echo "✅ Text output: $(TXT)"

html: $(HTML)

$(HTML): $(XML)
	$(XML2RFC) $(XML) --html
	@echo "✅ HTML output: $(HTML)"

validate:
	@$(XMLLINT) --noout $(XML) && echo "✅ XML well-formed: $(XML)"

clean:
	rm -f $(TXT) $(HTML)
	@echo "🧹 Cleaned generated RFC output files"

install:
	pip3 install xml2rfc
	@echo "✅ xml2rfc installed"

# Show build info
info:
	@echo "Draft:    $(DRAFT)"
	@echo "Source:   $(XML)"
	@echo "Outputs:  $(TXT)  $(HTML)"
	@$(XML2RFC) --version 2>&1 || true
