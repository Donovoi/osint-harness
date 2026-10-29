"""Reduce untrusted reports to a small, inert formatting vocabulary."""
from html import escape
from html.parser import HTMLParser
import base64
import hashlib

STYLE = 'body{font:14px system-ui,sans-serif;line-height:1.65;color:#243c46;margin:24px}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:inherit}table{border-collapse:collapse}td,th{border:1px solid #ddd;padding:8px}blockquote{border-left:3px solid #aac;padding-left:16px}'
CSP = "default-src 'none'; sandbox; style-src 'sha256-" + base64.b64encode(hashlib.sha256(STYLE.encode()).digest()).decode() + "'"

ALLOWED = {'p','br','h1','h2','h3','h4','ul','ol','li','strong','b','em','i','pre','code',
           'blockquote','table','thead','tbody','tr','th','td','hr','div','span','section','article'}
SKIP = {'script','style','iframe','object','svg','math','template','noscript','head'}

class Sanitizer(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self.skip = [], []
    def handle_starttag(self, tag, attrs):
        if self.skip:
            if tag in SKIP: self.skip.append(tag)
        elif tag in SKIP:
            self.skip.append(tag)
        elif tag in ALLOWED:
            self.parts.append('<' + tag + '>')
    def handle_startendtag(self, tag, attrs):
        if not self.skip and tag in ALLOWED:
            self.parts.append('<' + tag + '>')
    def handle_endtag(self, tag):
        if self.skip:
            if tag == self.skip[-1]: self.skip.pop()
        elif tag in ALLOWED and tag not in {'br','hr'}:
            self.parts.append('</' + tag + '>')
    def handle_data(self, data):
        if not self.skip: self.parts.append(escape(data))

def sanitize(raw):
    parser = Sanitizer()
    parser.feed(raw[:4*1024*1024])
    return '<!doctype html><html><head><meta charset="utf-8"><title>Working report</title><style>' + STYLE + '</style></head><body>' + ''.join(parser.parts) + '</body></html>'
