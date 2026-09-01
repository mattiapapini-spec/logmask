import re, html as htmllib, datetime
import markdown, pymupdf

DOCS = "./docs"
OUT = "./docs/LogMask_Technical_Documentation_EN_IT.pdf"

def md_to_html(path):
    text = open(path, encoding="utf-8").read()
    # drop the top H1 (we render a cover) and its subtitle line handled separately
    return markdown.markdown(text, extensions=["tables","fenced_code","toc","sane_lists"])

en = md_to_html(f"{DOCS}/en/TECHNICAL_DOCUMENTATION.md")
it = md_to_html(f"{DOCS}/it/DOCUMENTAZIONE_TECNICA.md")

CSS = """
* { font-family: sans-serif; }
h1 { font-size: 20pt; color: #1a3a5c; margin: 18pt 0 8pt 0; padding-bottom: 4pt;
     border-bottom: 2px solid #1a3a5c; }
h2 { font-size: 14pt; color: #1a3a5c; margin: 14pt 0 6pt 0; }
h3 { font-size: 11.5pt; color: #2c5578; margin: 10pt 0 4pt 0; }
p, li { font-size: 9.5pt; line-height: 1.45; color: #1a1a1a; }
li { margin: 2pt 0; }
code { font-family: monospace; font-size: 8.5pt; background-color: #eef1f4; color: #a03060; }
pre { font-family: monospace; font-size: 8pt; background-color: #eef2f6; color: #14304a;
      padding: 6pt; margin: 6pt 0; line-height: 1.4; }
pre code { background-color: #eef2f6; color: #14304a; }
table { width: 100%; border: 1px solid #c8d2dc; margin: 6pt 0; }
th { background-color: #1a3a5c; color: #ffffff; font-size: 8.5pt; text-align: left; padding: 4pt 6pt; }
td { font-size: 8.5pt; padding: 3pt 6pt; border-top: 1px solid #dce3ea; color: #1a1a1a; vertical-align: top; }
blockquote { background-color: #fbf3e0; border-left: 3px solid #d9a520; margin: 8pt 0;
             padding: 6pt 10pt; font-size: 9pt; color: #5a4a20; }
strong { color: #14304a; }
a { color: #1a3a5c; }
"""

def cover_html(title, subtitle, lang_note):
    return f"""
    <div style="margin-top:190pt; text-align:center;">
      <div style="font-size:34pt; color:#1a3a5c; font-family:sans-serif;"><b>LogMask</b></div>
      <div style="font-size:15pt; color:#2c5578; margin-top:10pt;">{title}</div>
      <div style="font-size:11pt; color:#555555; margin-top:24pt;">{subtitle}</div>
      <div style="font-size:10pt; color:#777777; margin-top:8pt;">Version 0.27.6</div>
      <div style="font-size:9pt; color:#999999; margin-top:60pt;">{lang_note}</div>
    </div>
    """

MEDIABOX = pymupdf.paper_rect("a4")
MARGIN = 52
WHERE = MEDIABOX + (MARGIN, MARGIN, -MARGIN, -MARGIN)

writer = pymupdf.DocumentWriter(OUT)

def render(html_body, css, footer):
    story = pymupdf.Story(html=html_body, user_css=css)
    more = True
    pageno_local = 0
    while more:
        dev = writer.begin_page(MEDIABOX)
        more, _ = story.place(WHERE)
        story.draw(dev)
        writer.end_page()

# Build one big HTML per section; cover pages as their own stories
sections = [
    (cover_html("Technical Documentation",
                "Reversible, fail-closed pseudonymization of SOC logs",
                "English &nbsp;·&nbsp; Italiano segue"), ""),
    (en, CSS),
    (cover_html("Documentazione Tecnica",
                "Pseudonimizzazione reversibile e fail-closed di log SOC",
                "Italiano"), ""),
    (it, CSS),
]
for body, css in sections:
    story = pymupdf.Story(html=body, user_css=css or CSS)
    more = True
    while more:
        dev = writer.begin_page(MEDIABOX)
        more, _ = story.place(WHERE)
        story.draw(dev)
        writer.end_page()
writer.close()

# post-process: add page numbers + footer with pymupdf
doc = pymupdf.open(OUT)
gen = datetime.date.today().isoformat()
for i, page in enumerate(doc):
    n = i + 1
    page.insert_text((MARGIN, MEDIABOX.height - 30), "LogMask 0.27.6 — Technical Documentation",
                     fontsize=7, color=(0.5,0.5,0.5))
    page.insert_text((MEDIABOX.width - MARGIN - 40, MEDIABOX.height - 30), f"{n} / {doc.page_count}",
                     fontsize=7, color=(0.5,0.5,0.5))
doc.set_metadata({"title":"LogMask 0.27.6 — Technical Documentation (EN/IT)",
                  "author":"LogMask", "subject":"Technical documentation"})
doc.save(OUT + ".tmp", garbage=4, deflate=True); doc.close()
import os; os.replace(OUT + ".tmp", OUT)
d = pymupdf.open(OUT); print("PDF pagine:", d.page_count); 
print("testo estraibile pagina 2 (inizio EN):", d[1].get_text()[:60].replace("\n"," "))
d.close()
