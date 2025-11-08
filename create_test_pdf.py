#!/usr/bin/env python3
"""
Create a test PDF file for the PDF Carrier encryption system
"""

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from datetime import datetime

def create_test_pdf(filename="test_document.pdf"):
    """Create a test PDF document"""

    # Create the PDF document
    doc = SimpleDocTemplate(filename, pagesize=letter)
    story = []
    styles = getSampleStyleSheet()

    # Add custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#2563eb'),
        spaceAfter=30,
        alignment=1  # Center
    )

    # Title
    title = Paragraph("PDF Carrier Test Document", title_style)
    story.append(title)
    story.append(Spacer(1, 0.2*inch))

    # Introduction
    intro = Paragraph(
        "<b>Purpose:</b> This is a test document for the PDF Carrier secure file encryption system.",
        styles['Normal']
    )
    story.append(intro)
    story.append(Spacer(1, 0.2*inch))

    # Project Information
    project_info = Paragraph("<b>Project: PDF Carrier - Secure File Encryption System</b>", styles['Heading2'])
    story.append(project_info)
    story.append(Spacer(1, 0.1*inch))

    description = Paragraph(
        """
        This cryptography course project demonstrates advanced encryption concepts including:<br/>
        • Hybrid encryption (RSA + AES + ChaCha20)<br/>
        • Multi-layer security (defense in depth)<br/>
        • Kerckhoffs's Principle (algorithm transparency)<br/>
        • Perfect forward secrecy<br/>
        • Authenticated encryption with HMAC<br/>
        """,
        styles['Normal']
    )
    story.append(description)
    story.append(Spacer(1, 0.3*inch))

    # Encryption Algorithms Table
    story.append(Paragraph("<b>Encryption Algorithms Used:</b>", styles['Heading2']))
    story.append(Spacer(1, 0.1*inch))

    data = [
        ['Algorithm', 'Type', 'Key Size', 'Purpose'],
        ['AES-256-GCM', 'Symmetric', '256 bits', 'Layer 1 encryption'],
        ['ChaCha20-Poly1305', 'Symmetric', '256 bits', 'Layer 2 encryption'],
        ['RSA-OAEP', 'Asymmetric', '4096 bits', 'Key encapsulation'],
        ['HMAC-SHA256', 'MAC', '256 bits', 'Integrity verification'],
    ]

    table = Table(data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2563eb')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(table)
    story.append(Spacer(1, 0.3*inch))

    # Security Features
    story.append(Paragraph("<b>Security Features:</b>", styles['Heading2']))
    story.append(Spacer(1, 0.1*inch))

    features = [
        "1. <b>Multi-layer Encryption:</b> Sequential application of 2 encryption algorithms provides defense in depth.",
        "2. <b>Random Algorithm Selection:</b> System randomly chooses which algorithms to use for each encryption.",
        "3. <b>Authenticated Encryption:</b> Both AES-GCM and ChaCha20-Poly1305 provide built-in authentication.",
        "4. <b>HMAC Verification:</b> Additional integrity check detects any tampering.",
        "5. <b>Perfect Forward Secrecy:</b> Unique keys generated for each encryption session.",
        "6. <b>Kerckhoffs's Principle:</b> Algorithm metadata stored in file header (not secret).",
    ]

    for feature in features:
        story.append(Paragraph(feature, styles['Normal']))
        story.append(Spacer(1, 0.1*inch))

    story.append(Spacer(1, 0.2*inch))

    # Test Instructions
    story.append(Paragraph("<b>How to Test:</b>", styles['Heading2']))
    story.append(Spacer(1, 0.1*inch))

    instructions = Paragraph(
        """
        1. <b>Encrypt:</b> Upload this PDF to the encryption page<br/>
        2. <b>Download:</b> Save both the encrypted file and key file<br/>
        3. <b>Decrypt:</b> Upload both files to the decryption page<br/>
        4. <b>Verify:</b> Compare the decrypted PDF with this original<br/>
        <br/>
        <b>Expected Result:</b> The decrypted file should be identical to this original document.
        """,
        styles['Normal']
    )
    story.append(instructions)
    story.append(Spacer(1, 0.3*inch))

    # Footer
    footer = Paragraph(
        f"<i>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i><br/>"
        f"<i>Document ID: TEST-PDF-{datetime.now().strftime('%Y%m%d%H%M%S')}</i>",
        styles['Normal']
    )
    story.append(Spacer(1, 0.5*inch))
    story.append(footer)

    # Build PDF
    doc.build(story)
    print(f"✅ Test PDF created: {filename}")
    print(f"   File size: {len(open(filename, 'rb').read())} bytes")
    return filename

if __name__ == "__main__":
    create_test_pdf()
