# main.py

import os
import json
import asyncio
import tempfile
import socket
from pydantic import BaseModel
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# --- Your Scanning and Reporting Functions ---
import whois
import requests
import google.generativeai as genai
import markdown
from datetime import datetime
from reportlab.platypus import BaseDocTemplate, PageTemplate, Frame, Paragraph, Spacer, PageBreak, ListFlowable, ListItem
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from reportlab.lib import colors
from bs4 import BeautifulSoup

# --- Selenium Imports for PublicWWW ---
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from urllib.parse import quote_plus


# --- Load Environment Variables ---
load_dotenv()
VT_API_KEY = "e3d85a9fe98800a129b860f1ad4e3c1e55f17e2ff144f11cd0445698620d6aa8" # Your VirusTotal key
URLSCAN_API_KEY = "01993ee0-357b-74b2-b7d1-247e7f143aa0" # Your urlscan.io key
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# --- FastAPI App Initialization ---
app = FastAPI(title="Security Scan and Report API", version="2.1.0")
origins = ["http://localhost:3000", "http://127.0.0.1:3000"]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# --- ASYNCHRONOUS SCANNING FUNCTIONS ---

async def run_in_thread(func, *args, **kwargs):
    """Helper to run blocking functions in a separate thread."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, lambda: func(*args, **kwargs))

def get_vt_report_sync(resource: str):
    url = "https://www.virustotal.com/vtapi/v2/url/report"
    params = {"apikey": VT_API_KEY, "resource": resource}
    try:
        resp = requests.get(url, params=params)
        resp.raise_for_status()
        return resp.json()
    except Exception as e: return {"error": str(e)}

async def get_vt_report(resource: str):
    return await run_in_thread(get_vt_report_sync, resource)

async def get_whois_json(domain: str):
    try:
        return await run_in_thread(lambda: {k: str(v) for k, v in whois.whois(domain).items()})
    except Exception as e: return {"error": str(e)}

def ssl_labs_scan_sync(host: str):
    api_url = "https://api.ssllabs.com/api/v3/analyze"
    params = {"host": host, "all": "done", "startNew": "on"}
    try:
        response = requests.get(api_url, params=params)
        response.raise_for_status()
        data = response.json()
        while data.get("status") in ["DNS", "IN_PROGRESS"]:
            import time; time.sleep(10)
            response = requests.get(api_url, params={"host": host, "all": "done"})
            response.raise_for_status()
            data = response.json()
        return data
    except Exception as e: return {"error": str(e)}

async def ssl_labs_scan(host: str):
    return await run_in_thread(ssl_labs_scan_sync, host)

def crtsh_scan_sync(domain: str):
    try:
        r = requests.get(f"https://crt.sh/?q={domain}&output=json")
        r.raise_for_status()
        return r.json()
    except Exception as e: return {"error": str(e)}

async def crtsh_scan(domain: str):
    return await run_in_thread(crtsh_scan_sync, domain)
    
def security_headers_scan_sync(url: str):
    try:
        r = requests.get(f"https://{url}" if not url.startswith('http') else url, allow_redirects=True, timeout=10)
        headers = r.headers
        security_headers_check = {
            "content_security_policy": "Content-Security-Policy" in headers,
            "strict_transport_security": "Strict-Transport-Security" in headers,
            "x_content_type_options": "X-Content-Type-Options" in headers,
            "x_frame_options": "X-Frame-Options" in headers,
            "x_xss_protection": "X-XSS-Protection" in headers,
        }
        return {"url": url, "headers_found": security_headers_check}
    except Exception as e: return {"error": str(e)}

async def security_headers_scan(url: str):
    return await run_in_thread(security_headers_scan_sync, url)
    
def urlscan_scan_sync(url: str):
    headers = {'API-Key': URLSCAN_API_KEY, 'Content-Type': 'application/json'}
    data = {"url": url, "visibility": "private"}
    try:
        r = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json=data)
        r.raise_for_status()
        submission = r.json()
        if submission.get("message") != "Submission successful":
            return {"error": "urlscan.io submission failed."}
        
        result_api = submission['api']
        import time; time.sleep(15) # Wait before first poll
        
        for _ in range(10): # Poll up to 10 times
            res = requests.get(result_api)
            if res.status_code == 200:
                return res.json()
            time.sleep(10)
        return {"error": "urlscan.io timed out."}
    except Exception as e: return {"error": str(e)}

async def urlscan_scan(url: str):
    return await run_in_thread(urlscan_scan_sync, url)

def publicwww_scan_sync(domain: str):
    opts = Options()
    opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    
    try:
        service = ChromeDriverManager().install()
        driver = webdriver.Chrome(service=webdriver.chrome.service.Service(service), options=opts)
        
        query = f"site:{domain}"
        driver.get(f"https://publicwww.com/?q={quote_plus(query)}")
        
        results = []
        rows = driver.find_elements(By.CSS_SELECTOR, "table.table tbody tr")[1:6] # Get top 5
        for row in rows:
            try:
                link_el = row.find_element(By.CSS_SELECTOR, "td:nth-of-type(2) a")
                link = link_el.get_attribute("href")
                snippet = row.find_element(By.CSS_SELECTOR, "td:nth-of-type(3)").text.strip()
                results.append({"link": link, "snippet": snippet})
            except: continue
        driver.quit()
        return {"results_count": len(results), "results": results}
    except Exception as e: return {"error": str(e)}

async def publicwww_scan(domain: str):
    return await run_in_thread(publicwww_scan_sync, domain)
    
def bgp_view_scan_sync(domain: str):
    try:
        ip_address = socket.gethostbyname(domain)
        response = requests.get(f"https://api.bgpview.io/ip/{ip_address}")
        response.raise_for_status()
        return response.json()
    except Exception as e: return {"error": str(e)}

async def bgp_view_scan(domain: str):
    return await run_in_thread(bgp_view_scan_sync, domain)

# --- SCANNER MAPPING (EXPANDED) ---
SCANNER_MAP = {
    "whois": get_whois_json,
    "virustotal": get_vt_report,
    "ssllabs": ssl_labs_scan,
    "crtsh": crtsh_scan,
    "security_headers": security_headers_scan,
    "urlscan": urlscan_scan,
    "publicwww": publicwww_scan,
    "bgpview": bgp_view_scan,
}

# --- REPORT GENERATION SCRIPT (REMAINS THE SAME) ---
# ... (Your entire `generate_and_save_report` function and its helpers go here, no changes needed)
def add_header_footer(c, doc):
    c.setFont("Helvetica-Bold", 10)
    c.drawString(30, A4[1] - 40, "Cybersecurity Analysis Report")
    page_num = c.getPageNumber()
    c.setFont("Helvetica", 9)
    c.drawString(30, 20, "© 2025 DeepCytes CyberLabs.")
    c.drawRightString(A4[0] - 30, 20, f"{page_num}")

class MyDocTemplate(BaseDocTemplate):
    def afterFlowable(self, flowable):
        if hasattr(flowable, "style") and flowable.style.name in ["CustomHeading1", "CustomHeading2"]:
            text = flowable.getPlainText()
            level = 0 if flowable.style.name == "CustomHeading1" else 1
            if text not in ["Cybersecurity Analysis Report", "Table of Contents"]:
                self.notify('TOCEntry', (level, text, self.page))

def generate_and_save_report(results_file: str, output_path: str):
    with open(results_file, 'r', encoding='utf-8') as f:
        scan_data = json.load(f)

    if not GEMINI_API_KEY:
        raise ValueError("GEMINI_API_KEY is not set.")

    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel("gemini-2.0-flash")
    data_as_string = json.dumps(scan_data, indent=2)
    prompt = f"""
You are a senior cybersecurity analyst. Analyze the provided reconnaissance scan data (JSON) and create a professional, structured security report in Markdown.

### Formatting Rules:
- Use `#` for main sections: **Summary**, **Detailed Findings**, **Recommendations**.
- Use `##` for each tool in **Detailed Findings** (e.g., "VirusTotal", "WHOIS").
- Use bullet points (`-`) for lists.
- Use **bold** for risk ratings (e.g., **Critical**, **High**) and key terms.
- Use inline code formatting (`) for technical values.
- Each subsection must end with a short *Takeaway* line in italics.

### Content Requirements:
1.  **Summary**: High-level overview and a final **Overall Risk Rating**.
2.  **Detailed Findings**: A section for each tool with bulleted results.
3.  **Recommendations**: Prioritized, actionable steps (Critical, High, Medium, Low).

RAW SCAN DATA:
{data_as_string}
"""
    response = model.generate_content(prompt)
    report_markdown = response.text
    report_html = markdown.markdown(report_markdown)

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="CustomHeading1", fontSize=18, leading=22, spaceAfter=12, textColor=colors.darkblue, fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle(name="CustomHeading2", fontSize=14, leading=18, spaceAfter=8, textColor=colors.darkred, fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle(name="CustomBodyText", fontSize=11, leading=14, spaceAfter=6))
    
    doc = MyDocTemplate(output_path, pagesize=A4)
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="normal")
    template = PageTemplate(id="with_header_footer", frames=frame, onPage=add_header_footer)
    doc.addPageTemplates([template])
    
    story = []
    # Cover Page & TOC
    story.extend([Spacer(1, 200), Paragraph("Cybersecurity Analysis Report", styles["CustomHeading1"]), Spacer(1, 20), Paragraph(f"Target: {scan_data.get('target', 'N/A')}", styles["CustomBodyText"]), Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d')}", styles["CustomBodyText"]), PageBreak()])
    toc = TableOfContents()
    toc.levelStyles = [ParagraphStyle(fontName="Helvetica-Bold", fontSize=14, name="TOCHeading1", leftIndent=20), ParagraphStyle(fontSize=12, name="TOCHeading2", leftIndent=40)]
    story.extend([Paragraph("Table of Contents", styles["CustomHeading1"]), toc, PageBreak()])

    # Report Content
    soup = BeautifulSoup(report_html, "html.parser")
    for element in soup.contents:
        if not hasattr(element, 'name') or not element.name: continue
        if element.name == "h1": story.append(Paragraph(element.get_text(), styles["CustomHeading1"]))
        elif element.name == "h2": story.append(Paragraph(element.get_text(), styles["CustomHeading2"]))
        elif element.name == "p": story.append(Paragraph(element.get_text(), styles["CustomBodyText"]))
        elif element.name in ("ul", "ol"):
            items = [ListItem(Paragraph(li.get_text(), styles["CustomBodyText"])) for li in element.find_all("li")]
            story.append(ListFlowable(items, bulletType="1" if element.name == "ol" else "bullet"))
    
    doc.multiBuild(story)
    return output_path

# --- API ENDPOINT (REMAINS THE SAME) ---
class ReportRequest(BaseModel):
    target: str
    scanners: list[str]

@app.post("/generate-report")
async def generate_report_endpoint(request: ReportRequest):
    if not request.target or not request.scanners:
        raise HTTPException(status_code=400, detail="Target and at least one scanner must be provided.")

    tasks = [SCANNER_MAP[name](request.target) for name in request.scanners if name in SCANNER_MAP]
    scan_results_list = await asyncio.gather(*tasks)

    all_results = {"target": request.target}
    for i, scanner_name in enumerate(request.scanners):
        if scanner_name in SCANNER_MAP:
            all_results[scanner_name] = scan_results_list[i]
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".json") as f_json, \
         tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as f_pdf:
        json.dump(all_results, f_json, indent=4)
        temp_json_path = f_json.name
        temp_pdf_path = f_pdf.name
    
    try:
        await run_in_thread(generate_and_save_report, temp_json_path, temp_pdf_path)
        return FileResponse(path=temp_pdf_path, media_type='application/pdf', filename=f"Security_Report_{request.target}.pdf")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if os.path.exists(temp_json_path): os.remove(temp_json_path)
