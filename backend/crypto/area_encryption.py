"""
Area-Based PDF Encryption Module

Handles selective encryption of specific rectangular areas in PDFs:
1. Overlay encrypted text boxes on top of original PDF
2. Original content is preserved except selected areas are covered
3. Decryption reverses this process
"""

import io
import base64
import json
from typing import List, Dict, Tuple, Optional
from pypdf import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.colors import white, black, Color


class AreaSelection:
    """Represents a selected area for encryption"""

    def __init__(self, page_number: int, x: float, y: float,
                 width: float, height: float, selection_id: str = None):
        self.page_number = page_number  # 1-indexed
        self.x = x  # PDF coordinates (bottom-left origin)
        self.y = y
        self.width = width
        self.height = height
        self.id = selection_id or f"area_{page_number}_{int(x)}_{int(y)}"

    def contains_point(self, px: float, py: float) -> bool:
        """Check if a point is within this area"""
        return (self.x <= px <= self.x + self.width and
                self.y <= py <= self.y + self.height)

    def to_dict(self) -> dict:
        return {
            'id': self.id,
            'page_number': self.page_number,
            'x': self.x,
            'y': self.y,
            'width': self.width,
            'height': self.height
        }

    @classmethod
    def from_dict(cls, data: dict, pdf_page_info: dict = None) -> 'AreaSelection':
        """
        Create AreaSelection from dict. If canvas coordinates are provided,
        transform them to PDF coordinates using the actual PDF page size.
        """
        page_num = data['page_number']

        # Check if we have normalized coordinates (new format - 0-1 range)
        if 'normalized_x' in data and pdf_page_info:
            # Get actual PDF page size
            pdf_dims = pdf_page_info['pages'].get(page_num, {'width': 612, 'height': 792})
            pdf_width = pdf_dims['width']
            pdf_height = pdf_dims['height']

            # Get normalized coordinates (0-1 range, origin at top-left of page)
            norm_x = data['normalized_x']
            norm_y = data['normalized_y']
            norm_w = data['normalized_width']
            norm_h = data['normalized_height']

            print(f"[COORD-TRANSFORM] Normalized: x={norm_x:.4f}, y={norm_y:.4f}, w={norm_w:.4f}, h={norm_h:.4f}")
            print(f"[COORD-TRANSFORM] PDF page size: {pdf_width:.1f} x {pdf_height:.1f}")

            # Convert to PDF coordinates
            # x and width are straightforward
            x = norm_x * pdf_width
            width = norm_w * pdf_width
            height = norm_h * pdf_height

            # Y needs to be flipped: normalized Y is from top, PDF Y is from bottom
            # The BOTTOM of the selection in PDF coords
            y = pdf_height - ((norm_y + norm_h) * pdf_height)

            print(f"[COORD-TRANSFORM] Result PDF coords: x={x:.1f}, y={y:.1f}, w={width:.1f}, h={height:.1f}")

            return cls(
                page_number=page_num,
                x=x,
                y=y,
                width=width,
                height=height,
                selection_id=data.get('id')
            )
        # Legacy: canvas coordinates format
        elif 'canvas_x' in data and pdf_page_info:
            # Get actual PDF page size
            pdf_dims = pdf_page_info['pages'].get(page_num, {'width': 612, 'height': 792})
            pdf_width = pdf_dims['width']
            pdf_height = pdf_dims['height']

            # Get canvas dimensions
            canvas_width = data.get('canvas_page_width', 612)
            canvas_height = data.get('canvas_page_height', 792)

            # Scale factors
            scale_x = pdf_width / canvas_width
            scale_y = pdf_height / canvas_height

            # Transform canvas coords to PDF coords
            # Canvas origin is top-left, PDF origin is bottom-left
            canvas_x = data['canvas_x']
            canvas_y = data['canvas_y']
            canvas_w = data['canvas_width']
            canvas_h = data['canvas_height']

            print(f"[COORD-TRANSFORM] Canvas: x={canvas_x:.1f}, y={canvas_y:.1f}, w={canvas_w:.1f}, h={canvas_h:.1f}")
            print(f"[COORD-TRANSFORM] Canvas page size: {canvas_width:.1f} x {canvas_height:.1f}")
            print(f"[COORD-TRANSFORM] PDF page size: {pdf_width:.1f} x {pdf_height:.1f}")
            print(f"[COORD-TRANSFORM] Scale factors: x={scale_x:.3f}, y={scale_y:.3f}")

            # Scale to PDF dimensions
            x = canvas_x * scale_x
            width = canvas_w * scale_x
            height = canvas_h * scale_y
            # Flip Y axis: PDF y=0 is at bottom
            y = pdf_height - ((canvas_y + canvas_h) * scale_y)

            print(f"[COORD-TRANSFORM] Result PDF coords: x={x:.1f}, y={y:.1f}, w={width:.1f}, h={height:.1f}")

            return cls(
                page_number=page_num,
                x=x,
                y=y,
                width=width,
                height=height,
                selection_id=data.get('id')
            )
        else:
            # Old format with direct PDF coordinates
            return cls(
                page_number=page_num,
                x=data['x'],
                y=data['y'],
                width=data['width'],
                height=data['height'],
                selection_id=data.get('id')
            )


def extract_text_with_positions(pdf_bytes: bytes) -> List[Dict]:
    """
    Extract text from PDF with position information using visitor pattern.
    Converts coordinates to standard PDF coordinate system (origin at bottom-left).
    """
    reader = PdfReader(io.BytesIO(pdf_bytes))
    all_text_elements = []

    for page_num, page in enumerate(reader.pages, 1):
        text_elements = []
        page_height = float(page.mediabox.height)

        # Check for page transformations (CropBox, MediaBox differences)
        mediabox = page.mediabox
        cropbox = page.cropbox if hasattr(page, 'cropbox') and page.cropbox else mediabox

        # Calculate any offset from cropbox
        y_offset = float(cropbox.bottom) if cropbox else 0
        x_offset = float(cropbox.left) if cropbox else 0

        print(f"[TEXT-EXTRACT] Page {page_num}: mediabox={mediabox}, height={page_height}")

        def visitor_body(text, cm, tm, font_dict, font_size):
            if text and text.strip():
                # tm is the text matrix [a, b, c, d, e, f]
                # e (tm[4]) is x position, f (tm[5]) is y position
                x = float(tm[4]) if tm else 0
                y = float(tm[5]) if tm else 0

                # If y is negative, it means the coordinate system is flipped
                # Convert to standard PDF coords (y=0 at bottom)
                if y < 0:
                    # The text position is given relative to top of page
                    # Convert: y_pdf = page_height + y (since y is negative)
                    y = page_height + y

                text_elements.append({
                    'page': page_num,
                    'text': text,
                    'x': x,
                    'y': y,
                    'font_size': float(font_size) if font_size else 12.0
                })

        page.extract_text(visitor_text=visitor_body)
        all_text_elements.extend(text_elements)

    return all_text_elements


def filter_text_in_areas(text_elements: List[Dict],
                         areas: List[AreaSelection]) -> Tuple[List[Dict], List[Dict]]:
    """
    Separate text elements into those inside and outside selected areas.
    Uses a more relaxed overlap check since text positions may not align exactly.
    """
    text_in_areas = []
    text_outside_areas = []

    # Debug: print first few text elements and area bounds
    if text_elements and areas:
        print(f"[FILTER] Area bounds: x={areas[0].x:.1f}-{areas[0].x + areas[0].width:.1f}, y={areas[0].y:.1f}-{areas[0].y + areas[0].height:.1f}")
        for i, elem in enumerate(text_elements[:10]):
            if elem['page'] == areas[0].page_number:
                print(f"[FILTER] Text {i}: '{elem['text'][:20]}...' at x={elem['x']:.1f}, y={elem['y']:.1f}")

    for element in text_elements:
        in_any_area = False
        for area in areas:
            if area.page_number == element['page']:
                # Check if text element overlaps with area
                # Text y is baseline position, so we need some tolerance
                text_x = element['x']
                text_y = element['y']
                font_size = element.get('font_size', 12)

                # IMPORTANT: pypdf returns text coordinates at the START of each text run,
                # not at individual word positions. So text_x is often at the left margin
                # even if the text visually appears further right in the line.
                #
                # We use a relaxed check: if the text's Y coordinate falls within the area,
                # we consider it a match. This captures entire lines that overlap vertically
                # with the selected area.
                #
                # PDF y increases upward, so area.y is bottom, area.y + area.height is top
                area_top = area.y + area.height
                area_bottom = area.y

                # Check if text baseline (with font height tolerance) overlaps with area vertically
                if (area_bottom - font_size <= text_y <= area_top + font_size):
                    in_any_area = True
                    element['area_id'] = area.id
                    print(f"[FILTER] MATCH: '{element['text'][:30]}' at ({text_x:.1f}, {text_y:.1f})")
                    break

        if in_any_area:
            text_in_areas.append(element)
        else:
            text_outside_areas.append(element)

    return text_in_areas, text_outside_areas


def get_pdf_page_info(pdf_bytes: bytes) -> Dict:
    """Get page dimensions and count from PDF"""
    reader = PdfReader(io.BytesIO(pdf_bytes))
    pages_info = {}

    for page_num, page in enumerate(reader.pages, 1):
        pages_info[page_num] = {
            'width': float(page.mediabox.width),
            'height': float(page.mediabox.height)
        }

    return {
        'page_count': len(reader.pages),
        'pages': pages_info
    }


def create_overlay_pdf(
    page_info: Dict,
    encrypted_text_mapping: Dict[str, str],
    areas: List[AreaSelection]
) -> bytes:
    """
    Create a PDF with only the encrypted area overlays (white boxes with encrypted text)
    """
    output = io.BytesIO()
    page_count = page_info['page_count']

    c = canvas.Canvas(output)

    for page_num in range(1, page_count + 1):
        page_dims = page_info['pages'].get(page_num, {'width': 612, 'height': 792})
        page_width = page_dims['width']
        page_height = page_dims['height']

        c.setPageSize((page_width, page_height))

        # Draw encrypted overlays for this page
        page_areas = [a for a in areas if a.page_number == page_num]
        for area in page_areas:
            encrypted_text = encrypted_text_mapping.get(area.id, '[ENCRYPTED]')

            # Draw white background to cover original content (no border)
            c.setFillColor(white)
            c.rect(area.x, area.y, area.width, area.height, fill=True, stroke=False)

            # Draw encrypted text within area (fills the entire area)
            c.setFillColor(black)
            draw_text_in_area(c, encrypted_text, area)

        c.showPage()

    c.save()
    output.seek(0)
    return output.read()


def create_pdf_with_selective_encryption(
    original_pdf_bytes: bytes,
    encrypted_text_mapping: Dict[str, str],
    areas: List[AreaSelection],
    page_info: Dict
) -> bytes:
    """
    Create a new PDF by overlaying encrypted boxes on top of the original PDF.
    This preserves all original content except the selected areas.
    """
    # Create overlay with encrypted areas
    overlay_pdf_bytes = create_overlay_pdf(page_info, encrypted_text_mapping, areas)

    # Read original PDF
    original_reader = PdfReader(io.BytesIO(original_pdf_bytes))

    # Read overlay PDF
    overlay_reader = PdfReader(io.BytesIO(overlay_pdf_bytes))

    # Create output PDF
    writer = PdfWriter()

    # Merge overlay onto each page
    for page_num in range(len(original_reader.pages)):
        original_page = original_reader.pages[page_num]

        if page_num < len(overlay_reader.pages):
            overlay_page = overlay_reader.pages[page_num]
            # Merge overlay on top of original
            original_page.merge_page(overlay_page)

        writer.add_page(original_page)

    # Write output
    output = io.BytesIO()
    writer.write(output)
    output.seek(0)
    return output.read()


def draw_text_in_area(canvas_obj, text: str, area: AreaSelection,
                      font_size: int = 6):
    """
    Draw text within a rectangular area with automatic wrapping.
    Fills the entire area by repeating the encrypted text as needed.
    """
    canvas_obj.setFont('Courier', font_size)

    char_width = font_size * 0.6
    chars_per_line = max(1, int(area.width / char_width))
    line_height = font_size * 1.2

    # Calculate how many lines fit in the area
    max_lines = max(1, int(area.height / line_height))

    # Calculate total characters needed to fill the area
    total_chars_needed = chars_per_line * max_lines

    # Repeat the text to fill the entire area
    if len(text) < total_chars_needed:
        # Repeat text to fill the area
        repeated_text = (text * ((total_chars_needed // len(text)) + 1))[:total_chars_needed]
    else:
        repeated_text = text

    # Split into lines
    lines = [repeated_text[i:i+chars_per_line] for i in range(0, len(repeated_text), chars_per_line)]

    y_pos = area.y + area.height - line_height
    for line in lines:
        if y_pos < area.y:
            break
        canvas_obj.drawString(area.x + 2, y_pos, line)
        y_pos -= line_height


def group_text_by_area(text_in_areas: List[Dict], areas: List[AreaSelection]) -> Dict[str, Dict]:
    """Group text elements by their area ID"""
    area_content = {}

    for area in areas:
        area_content[area.id] = {
            'text': '',
            'elements': []
        }

    for text_elem in text_in_areas:
        area_id = text_elem.get('area_id')
        if area_id and area_id in area_content:
            area_content[area_id]['elements'].append(text_elem)
            area_content[area_id]['text'] += text_elem['text'] + ' '

    for area_id in area_content:
        area_content[area_id]['text'] = area_content[area_id]['text'].strip()

    return area_content


def encrypt_area_content(content: str, encrypt_func) -> bytes:
    """Encrypt text content using the provided encryption function"""
    if not content:
        return b''

    content_bytes = content.encode('utf-8')
    return encrypt_func(content_bytes)


def decrypt_area_content(encrypted_bytes: bytes, decrypt_func) -> str:
    """Decrypt encrypted content using the provided decryption function"""
    if not encrypted_bytes:
        return ''

    decrypted_bytes = decrypt_func(encrypted_bytes)
    return decrypted_bytes.decode('utf-8')


__all__ = [
    'AreaSelection',
    'extract_text_with_positions',
    'filter_text_in_areas',
    'get_pdf_page_info',
    'create_pdf_with_selective_encryption',
    'create_overlay_pdf',
    'draw_text_in_area',
    'group_text_by_area',
    'encrypt_area_content',
    'decrypt_area_content'
]
