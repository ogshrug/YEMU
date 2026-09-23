from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import json
import os
from yemu import paths

class ReportStore:
    def __init__(self, output_dir=None):
        self.output_dir = str(output_dir or paths.reports_dir())
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_pdf(self, analysis_id, data):
        filename = f"report_{analysis_id}.pdf"
        filepath = os.path.join(self.output_dir, filename)

        c = canvas.Canvas(filepath, pagesize=letter)
        c.setFont("Helvetica-Bold", 16)
        c.drawString(100, 750, f"Malware Analysis Report: {data['filename']}")

        c.setFont("Helvetica", 12)
        c.drawString(100, 730, f"SHA256: {data['sha256']}")
        c.drawString(100, 715, f"Threat Score: {data['score']}/100")
        c.drawString(100, 700, f"Verdict: {data['verdict'].upper()}")

        c.drawString(100, 670, "IOCs:")
        y = 650
        for ioc in data.get('iocs', []):
            c.drawString(120, y, f"- {ioc['type']}: {ioc['value']}")
            y -= 15

        c.save()
        return filepath

    def save_json(self, analysis_id, data):
        filename = f"report_{analysis_id}.json"
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        return filepath
