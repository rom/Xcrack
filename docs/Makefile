# Build printable PDF manuals from the Markdown docs.
#
# Requires pandoc (https://pandoc.org) and a PDF engine. Any one of these works,
# tried in order unless you set PDF_ENGINE explicitly:
#   tectonic | xelatex | lualatex | pdflatex | wkhtmltopdf
#
#   make            # build the combined Xcrack-Manual.pdf (default)
#   make manual     # same
#   make usermanual # just USERMANUAL.pdf
#   make all-pdfs   # one PDF per source doc, under pdf/
#   make check      # report whether pandoc + a PDF engine are available
#   make clean      # remove built PDFs
#
# Note: Mermaid diagrams (README/CRACKING) render as fenced code unless a pandoc
# mermaid filter is installed; the prose around them stands on its own.

PANDOC      ?= pandoc
OUTDIR      ?= pdf
MANUAL      ?= Xcrack-Manual.pdf
TITLE       ?= Xcrack — User Manual & Reference
VERSION     ?= $(shell git -C .. describe --tags --always --dirty 2>/dev/null || echo unversioned)

# USERMANUAL first, then the reference docs in reading order. (Correct on-disk
# names: FILEFORMATS.md, REFERENCES.md.)
DOCS := USERMANUAL.md \
        USAGE.md \
        API.md \
        FILEFORMATS.md \
        CRACKING.md \
        PERFORMANCE.md \
        TERMINOLOGY.md \
        FAQ.md \
        REFERENCES.md

# Resolve a PDF engine if the caller did not pin one.
PDF_ENGINE ?= $(firstword $(foreach e,tectonic xelatex lualatex pdflatex wkhtmltopdf,$(if $(shell command -v $(e) 2>/dev/null),$(e))))

PANDOC_OPTS := --from=gfm \
               --toc --toc-depth=2 \
               --metadata title="$(TITLE)" \
               --metadata subtitle="version $(VERSION)" \
               --resource-path=.:..
ifneq ($(PDF_ENGINE),)
#PANDOC_OPTS += --pdf-engine=$(PDF_ENGINE)
PANDOC_OPTS += --defaults=pdf-fonts.yaml --pdf-engine=lualatex
endif

.PHONY: all manual usermanual all-pdfs check clean help
all: manual

# A tool guard: every PDF target depends on this.
.PHONY: require-pandoc
require-pandoc:
	@command -v $(PANDOC) >/dev/null 2>&1 || { \
	  echo "error: pandoc not found. Install it from https://pandoc.org (e.g. 'apt-get install pandoc' / 'brew install pandoc')."; exit 1; }
	@if [ -z "$(PDF_ENGINE)" ]; then \
	  echo "error: no PDF engine found. Install one of: tectonic, xelatex (texlive-xetex), lualatex, pdflatex, or wkhtmltopdf,"; \
	  echo "       or pass PDF_ENGINE=<engine> if it is installed under another name."; exit 1; fi

manual: require-pandoc
	@mkdir -p $(OUTDIR)
	$(PANDOC) $(PANDOC_OPTS) -o $(OUTDIR)/$(MANUAL) $(DOCS)
	@echo "built $(OUTDIR)/$(MANUAL)  (engine: $(PDF_ENGINE))"

usermanual: require-pandoc
	@mkdir -p $(OUTDIR)
	$(PANDOC) $(PANDOC_OPTS) --metadata title="Xcrack — User Manual" -o $(OUTDIR)/USERMANUAL.pdf USERMANUAL.md
	@echo "built $(OUTDIR)/USERMANUAL.pdf  (engine: $(PDF_ENGINE))"

all-pdfs: require-pandoc
	@mkdir -p $(OUTDIR)
	@for d in $(DOCS); do \
	  out="$(OUTDIR)/$${d%.md}.pdf"; \
	  echo "  $$d -> $$out"; \
	  $(PANDOC) $(PANDOC_OPTS) --metadata title="Xcrack — $${d%.md}" -o "$$out" "$$d" || exit 1; \
	done
	@echo "built per-doc PDFs under $(OUTDIR)/"

check:
	@if command -v $(PANDOC) >/dev/null 2>&1; then echo "pandoc:     $$($(PANDOC) --version | head -1)"; else echo "pandoc:     NOT FOUND"; fi
	@if [ -n "$(PDF_ENGINE)" ]; then echo "pdf-engine: $(PDF_ENGINE)"; else echo "pdf-engine: NONE (install tectonic/xelatex/pdflatex/wkhtmltopdf)"; fi

clean:
	rm -rf $(OUTDIR)

help:
	@echo "Targets: manual (default), usermanual, all-pdfs, check, clean."
	@echo "Needs pandoc + a PDF engine (PDF_ENGINE=$(PDF_ENGINE)). Run 'make check'."
