#!/bin/bash
# Generate PDF from compliance report
# Requires: pandoc and a LaTeX distribution (e.g., MacTeX, TeX Live)

set -euo pipefail

REPORT_DIR="$(dirname "$0")"
MD_FILE="$REPORT_DIR/FINAL_COMPLIANCE_REPORT.md"
PDF_FILE="$REPORT_DIR/FINAL_COMPLIANCE_REPORT.pdf"

# Check if pandoc is installed
if ! command -v pandoc &> /dev/null; then
    echo "Error: pandoc is not installed"
    echo "Install with: brew install pandoc (macOS) or apt-get install pandoc (Linux)"
    exit 1
fi

# Check if pdflatex is available (for better PDF output)
if command -v pdflatex &> /dev/null; then
    ENGINE="pdflatex"
elif command -v xelatex &> /dev/null; then
    ENGINE="xelatex"
else
    ENGINE="html"
    echo "Warning: No LaTeX engine found, using HTML-based PDF generation"
    echo "For better output, install MacTeX (macOS) or TeX Live (Linux)"
fi

echo "Generating PDF compliance report..."

if [ "$ENGINE" != "html" ]; then
    # Generate PDF with LaTeX engine
    pandoc "$MD_FILE" \
        -o "$PDF_FILE" \
        --pdf-engine="$ENGINE" \
        --toc \
        --toc-depth=3 \
        --highlight-style=tango \
        -V geometry:margin=1in \
        -V papersize=letter \
        -V fontsize=11pt \
        -V documentclass=report \
        -V colorlinks=true \
        -V linkcolor=blue \
        -V urlcolor=blue \
        -V toccolor=black \
        --metadata title="ANT-QUIC IETF Compliance Report" \
        --metadata author="ANT-QUIC Development Team" \
        --metadata date="$(date +%B\ %d,\ %Y)"
else
    # Fallback to HTML-based PDF
    pandoc "$MD_FILE" \
        -o "$PDF_FILE" \
        --toc \
        --toc-depth=3 \
        --highlight-style=tango \
        --metadata title="ANT-QUIC IETF Compliance Report" \
        --metadata author="ANT-QUIC Development Team" \
        --metadata date="$(date +%B\ %d,\ %Y)"
fi

if [ -f "$PDF_FILE" ]; then
    echo "✅ PDF report generated successfully: $PDF_FILE"
    echo "File size: $(du -h "$PDF_FILE" | cut -f1)"
    
    # Also create a simple HTML version for easy viewing
    HTML_FILE="$REPORT_DIR/FINAL_COMPLIANCE_REPORT.html"
    pandoc "$MD_FILE" \
        -o "$HTML_FILE" \
        --standalone \
        --toc \
        --toc-depth=3 \
        --highlight-style=tango \
        --css="https://cdn.jsdelivr.net/npm/github-markdown-css/github-markdown.min.css" \
        --metadata title="ANT-QUIC IETF Compliance Report"
    
    if [ -f "$HTML_FILE" ]; then
        echo "✅ HTML report also generated: $HTML_FILE"
    fi
else
    echo "❌ Failed to generate PDF report"
    exit 1
fi

echo
echo "Report generation complete!"
echo "- Markdown: $MD_FILE"
echo "- JSON: ${MD_FILE%.md}.json"
echo "- PDF: $PDF_FILE"
echo "- HTML: ${MD_FILE%.md}.html"