import json
import logging

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
except ImportError:
    letter = None

class PDFGenerator:
    def __init__(self, output_path):
        self.output_path = output_path
        self.logger = logging.getLogger(__name__)
        if letter:
            self.styles = getSampleStyleSheet()
        else:
            self.styles = None

    def generate(self, details, events):
        if not letter:
            self.logger.error("ReportLab not found. PDF generation disabled.")
            return

        doc = SimpleDocTemplate(self.output_path, pagesize=letter)
        elements = []

        # Title
        elements.append(Paragraph(f"Analysis Report: {details['filename']}", self.styles['Title']))
        elements.append(Spacer(1, 12))

        # Summary Table
        summary_data = [
            ["Attribute", "Value"],
            ["Verdict", details['verdict'] or "Unknown"],
            ["Threat Score", str(details['threat_score'] or 0)],
            ["SHA256", details['sha256']],
            ["MD5", details['md5']],
            ["Size", f"{details['size_bytes']} bytes"],
            ["Started At", details['started_at']],
            ["Finished At", details['finished_at']]
        ]
        t = Table(summary_data, colWidths=[100, 400])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(t)
        elements.append(Spacer(1, 24))

        # YARA Matches
        elements.append(Paragraph("YARA Matches", self.styles['Heading2']))
        yara_matches = json.loads(details['yara_matches']) if details['yara_matches'] else []
        if yara_matches:
            for match in yara_matches:
                if isinstance(match, dict):
                    rule = match.get('rule', 'unknown')
                    source = match.get('source', 'unknown').upper()
                    elements.append(Paragraph(f"Rule: <b>{rule}</b> ({source})", self.styles['Normal']))

                    # Meta & Tags
                    tags = match.get('tags', [])
                    if tags:
                        elements.append(Paragraph(f"<i>Tags: {', '.join(tags)}</i>", self.styles['Normal']))

                    meta = match.get('meta', {})
                    if meta:
                        for k, v in meta.items():
                            elements.append(Paragraph(f"  - {k}: {v}", self.styles['Normal']))

                    # Process context
                    if source == 'MEMORY':
                        pid = match.get('pid', 'N/A')
                        proc = match.get('process_name', 'unknown')
                        path = match.get('exe_path', 'unknown')
                        elements.append(Paragraph(f"  Context: PID {pid} ({proc}) - {path}", self.styles['Normal']))

                    # Strings
                    strings = match.get('strings', [])
                    if strings:
                        elements.append(Paragraph("  Matched Strings:", self.styles['Normal']))
                        for s in strings[:10]: # Limit to top 10 strings
                            elements.append(Paragraph(f"    {s['offset']}:{s['identifier']}: {s['data']}", self.styles['Normal']))
                        if len(strings) > 10:
                            elements.append(Paragraph(f"    ... and {len(strings)-10} more", self.styles['Normal']))
                else:
                    elements.append(Paragraph(f"• {match}", self.styles['Normal']))
                elements.append(Spacer(1, 6))
        else:
            elements.append(Paragraph("No YARA matches found.", self.styles['Normal']))
        elements.append(Spacer(1, 12))

        # Behavioral Events
        elements.append(Paragraph("Behavioral Events (Top 50)", self.styles['Heading2']))
        event_data = [["Time", "Type", "Event"]]
        for ev in events[:50]:
            ts = ev['timestamp']
            ev_type = ev['event_type']
            det = json.loads(ev['details']) if isinstance(ev['details'], str) else ev['details']

            if ev_type == 'process':
                desc = f"PID {det.get('pid')}: {det.get('action')} {det.get('path', '')}"
            elif ev_type == 'network':
                desc = f"Connect to {det.get('dst_ip')}:{det.get('dst_port')}"
            elif ev_type == 'file':
                desc = f"{det.get('action')} {det.get('path')}"
            else:
                desc = str(det)

            event_data.append([str(ts), ev_type, Paragraph(desc, self.styles['Normal'])])

        et = Table(event_data, colWidths=[60, 60, 380])
        et.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'TOP')
        ]))
        elements.append(et)

        doc.build(elements)
