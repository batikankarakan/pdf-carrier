"""
PDF Content Manipulation Module

Handles encryption of entire PDF files while maintaining structure.
Creates a PDF that shows encrypted content when opened.
"""

import io
import base64
from typing import Tuple
from pypdf import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch


def extract_text_from_pdf(pdf_bytes: bytes) -> Tuple[str, dict]:
    """
    Extract all text content from a PDF file (used for displaying encrypted content)

    Args:
        pdf_bytes: PDF file content as bytes

    Returns:
        Tuple of (extracted_text, metadata)
        - extracted_text: All text content from the PDF
        - metadata: Dict with page count and other info
    """
    reader = PdfReader(io.BytesIO(pdf_bytes))

    all_text = []
    for page_num, page in enumerate(reader.pages):
        text = page.extract_text()
        all_text.append(text)

    combined_text = "\n--- PAGE BREAK ---\n".join(all_text)

    metadata = {
        "page_count": len(reader.pages),
        "page_sizes": [
            {
                "width": page.mediabox.width,
                "height": page.mediabox.height
            }
            for page in reader.pages
        ]
    }

    return combined_text, metadata


def get_pdf_metadata(pdf_bytes: bytes) -> dict:
    """
    Extract metadata from PDF without extracting text

    Args:
        pdf_bytes: PDF file content as bytes

    Returns:
        Dict with page count and page sizes
    """
    reader = PdfReader(io.BytesIO(pdf_bytes))

    metadata = {
        "page_count": len(reader.pages),
        "page_sizes": [
            {
                "width": page.mediabox.width,
                "height": page.mediabox.height
            }
            for page in reader.pages
        ]
    }

    return metadata


def create_pdf_with_text(text: str, page_metadata: dict = None) -> bytes:
    """
    Create a new PDF with the given text content

    Args:
        text: Text content to put in the PDF
        page_metadata: Optional metadata about page sizes

    Returns:
        PDF file content as bytes
    """
    buffer = io.BytesIO()

    # Use letter size by default
    page_size = letter
    if page_metadata and page_metadata.get("page_sizes"):
        # Try to use original page size
        first_page = page_metadata["page_sizes"][0]
        page_size = (float(first_page["width"]), float(first_page["height"]))

    c = canvas.Canvas(buffer, pagesize=page_size)
    width, height = page_size

    # Split text into pages
    pages = text.split("\n--- PAGE BREAK ---\n")

    # Styling parameters
    margin = 0.75 * inch
    font_size = 10
    line_height = 14

    for page_text in pages:
        y_position = height - margin

        # Split into lines and wrap if needed
        lines = page_text.split('\n')

        for line in lines:
            # Simple wrapping: if line is too long, break it
            if len(line) > 80:
                # Break into chunks of 80 characters
                chunks = [line[i:i+80] for i in range(0, len(line), 80)]
                for chunk in chunks:
                    if y_position < margin:
                        c.showPage()
                        y_position = height - margin

                    c.setFont("Helvetica", font_size)
                    c.drawString(margin, y_position, chunk)
                    y_position -= line_height
            else:
                if y_position < margin:
                    c.showPage()
                    y_position = height - margin

                c.setFont("Helvetica", font_size)
                c.drawString(margin, y_position, line)
                y_position -= line_height

        # New page for each original page
        c.showPage()

    c.save()
    buffer.seek(0)
    return buffer.read()


def encrypt_text_content(text: str) -> str:
    """
    Convert text to encrypted representation (base64 encoded bytes)
    This creates gibberish that looks like encrypted content.

    Args:
        text: Plain text to encrypt representation

    Returns:
        String that looks like encrypted content
    """
    import base64
    # Convert to bytes and encode as base64 to make it look encrypted
    encrypted_bytes = text.encode('utf-8')
    encrypted_text = base64.b64encode(encrypted_bytes).decode('utf-8')

    # Break into chunks for readability in the PDF
    chunk_size = 64
    chunks = [encrypted_text[i:i+chunk_size] for i in range(0, len(encrypted_text), chunk_size)]

    return '\n'.join(chunks)


def decrypt_text_content(encrypted_text: str) -> str:
    """
    Decrypt text that was encrypted with encrypt_text_content

    Args:
        encrypted_text: Encrypted text from PDF

    Returns:
        Original plain text
    """
    import base64
    # Remove line breaks that were added for formatting
    encrypted_text = encrypted_text.replace('\n', '').replace(' ', '')

    # Decode from base64
    try:
        decrypted_bytes = base64.b64decode(encrypted_text)
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Failed to decrypt text content: {str(e)}")


__all__ = [
    'extract_text_from_pdf',
    'get_pdf_metadata',
    'create_pdf_with_text',
    'encrypt_text_content',
    'decrypt_text_content'
]
