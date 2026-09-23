import json
import logging
from xml.sax.saxutils import escape

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
            msg = "ReportLab not found. PDF generation disabled."
            self.logger.error(msg)
            raise RuntimeError(msg)

        doc = SimpleDocTemplate(self.output_path, pagesize=letter)
        elements = []

        # Title
        filename = escape(str(details.get('filename') or 'unknown'))
        elements.append(Paragraph(f"Analysis Report: {filename}", self.styles['Title']))
        elements.append(Spacer(1, 12))

        # Summary Table
        summary_data = [
            ["Attribute", "Value"],
            ["Verdict", escape(str(details.get('verdict') or "Unknown"))],
            ["Threat Score", str(details.get('threat_score') or 0)],
            ["SHA256", escape(str(details.get('sha256') or ""))],
            ["MD5", escape(str(details.get('md5') or ""))],
            ["Size", f"{details.get('size_bytes', 0)} bytes"],
            ["Started At", escape(str(details.get('started_at') or ""))],
            ["Finished At", escape(str(details.get('finished_at') or ""))]
        ]
        t = Table(summary_data, colWidths=[100, 350])
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
        try:
            yara_matches_raw = details.get('yara_matches')
            yara_matches = json.loads(yara_matches_raw) if yara_matches_raw else []
        except (json.JSONDecodeError, TypeError):
            yara_matches = []

        if yara_matches:
            for match in yara_matches:
                if isinstance(match, dict):
                    rule = escape(str(match.get('rule', 'unknown')))
                    source = escape(str(match.get('source', 'unknown')).upper())
                    elements.append(Paragraph(f"Rule: <b>{rule}</b> ({source})", self.styles['Normal']))

                    # Meta & Tags
                    tags = match.get('tags', [])
                    if tags:
                        escaped_tags = [escape(str(t)) for t in tags]
                        elements.append(Paragraph(f"<i>Tags: {', '.join(escaped_tags)}</i>", self.styles['Normal']))

                    meta = match.get('meta', {})
                    if meta:
                        for k, v in meta.items():
                            elements.append(Paragraph(f"  - {escape(str(k))}: {escape(str(v))}", self.styles['Normal']))

                    # Process context
                    if source == 'MEMORY':
                        pid = escape(str(match.get('pid', 'N/A')))
                        proc = escape(str(match.get('process_name', 'unknown')))
                        path = escape(str(match.get('exe_path', 'unknown')))
                        elements.append(Paragraph(f"  Context: PID {pid} ({proc}) - {path}", self.styles['Normal']))

                    # Strings
                    strings = match.get('strings', [])
                    if strings:
                        elements.append(Paragraph("  Matched Strings:", self.styles['Normal']))
                        for s in strings[:10]: # Limit to top 10 strings
                            s_id = escape(str(s.get('identifier', '')))
                            s_data = escape(str(s.get('data', '')))
                            s_offset = escape(str(s.get('offset', '')))
                            elements.append(Paragraph(f"    {s_offset}:{s_id}: {s_data}", self.styles['Normal']))
                        if len(strings) > 10:
                            elements.append(Paragraph(f"    ... and {len(strings)-10} more", self.styles['Normal']))
                else:
                    elements.append(Paragraph(f"• {escape(str(match))}", self.styles['Normal']))
                elements.append(Spacer(1, 6))
        else:
            elements.append(Paragraph("No YARA matches found.", self.styles['Normal']))
        elements.append(Spacer(1, 12))

        # Behavioral Events
        elements.append(Paragraph("Behavioral Events (Top 50)", self.styles['Heading2']))
        event_data = [["Time", "Type", "Event"]]
        safe_events = events or []
        for ev in safe_events[:50]:
            ts = ev.get('timestamp', '')
            ev_type = ev.get('event_type', 'unknown')
            try:
                det = json.loads(ev['details']) if isinstance(ev['details'], str) else ev.get('details', {})
            except (json.JSONDecodeError, TypeError):
                det = {}

            if ev_type == 'process':
                desc = f"PID {det.get('pid', 'N/A')}: {det.get('action', 'unknown')} {det.get('path', '')}"
            elif ev_type == 'network':
                desc = f"Connect to {det.get('dst_ip', 'unknown')}:{det.get('dst_port', 'unknown')}"
            elif ev_type == 'file':
                desc = f"{det.get('action', 'unknown')} {det.get('path', 'unknown')}"
            else:
                desc = str(det)

            event_data.append([str(ts), ev_type, Paragraph(escape(desc), self.styles['Normal'])])

        et = Table(event_data, colWidths=[60, 60, 330])
        et.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'TOP')
        ]))
        elements.append(et)

        try:
            doc.build(elements)
            self.logger.info(f"Successfully generated PDF report at {self.output_path}")
        except Exception as e:
            self.logger.error(f"Error building PDF doc: {e}")
            raise
