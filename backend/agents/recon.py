"""Recon agent: fetch, parse, crawl, fingerprint across fan-out targets.

Pure Python (httpx + bs4). Iterates context.targets (root URL + live
subdomains from the surface stage), aggregating pages/forms/headers/tech.
"""

import asyncio
import re
from urllib.parse import urljoin, urlsplit
from urllib.robotparser import RobotFileParser

import httpx
from bs4 import BeautifulSoup

USER_AGENT = "VulnAgent/0.1 (authorized security testing)"
MAX_PAGES_PER_TARGET = 30
MAX_DEPTH = 2
LIGHT_MAX_PAGES = 12
LIGHT_DEPTH = 1

TECH_SIGNATURES = [
    (re.compile(r"wordpress|wp-content|wp-includes", re.I), "WordPress"),
    (re.compile(r"drupal", re.I), "Drupal"),
    (re.compile(r"joomla", re.I), "Joomla"),
    (re.compile(r"laravel", re.I), "Laravel"),
    (re.compile(r"django", re.I), "Django"),
    (re.compile(r"flask", re.I), "Flask"),
    (re.compile(r"express|node\.js", re.I), "Node.js/Express"),
    (re.compile(r"react", re.I), "React"),
    (re.compile(r"next\.js|__next", re.I), "Next.js"),
    (re.compile(r"vue\.js", re.I), "Vue.js"),
    (re.compile(r"asp\.net|iis", re.I), "ASP.NET/IIS"),
    (re.compile(r"php", re.I), "PHP"),
    (re.compile(r"nginx", re.I), "nginx"),
    (re.compile(r"apache", re.I), "Apache"),
    (re.compile(r"cloudflare", re.I), "Cloudflare"),
    (re.compile(r"akamai", re.I), "Akamai"),
]

HTML_CTYPES = ("text/html", "application/xhtml+xml")


class ReconAgent:
    name = "recon"

    async def run(self, context):
        targets = list(getattr(context, "targets", None) or [context.url])
        pages = []
        forms = []
        all_headers = {}
        meta_generators = []
        visited_all = []

        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=10.0,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            for target in targets:
                base = _normalize(target)
                host = urlsplit(base).netloc
                robots = await _load_robots(base, host)
                visited = set()
                sem = asyncio.Semaphore(10)
                light = context.scan_mode == "light"
                max_pages = LIGHT_MAX_PAGES if light else MAX_PAGES_PER_TARGET
                max_depth = LIGHT_DEPTH if light else MAX_DEPTH

                async def crawl_one(url):
                    async with sem:
                        resp = await _fetch(client, url)
                        if resp is None:
                            return None, None
                        page = {
                            "url": str(resp.url),
                            "status": resp.status_code,
                            "headers": dict(resp.headers),
                            "ctype": resp.headers.get("content-type", ""),
                        }
                        soup = None
                        if resp.status_code < 400:
                            ctype = resp.headers.get("content-type", "")
                            if any(c in ctype for c in HTML_CTYPES):
                                soup = BeautifulSoup(resp.text, "html.parser")
                        return page, soup

                level = [(base, 0)]
                while level and len(visited) < max_pages:
                    urls = []
                    for url, depth in level:
                        if url in visited or (robots and not robots.can_fetch("*", url)):
                            continue
                        visited.add(url)
                        urls.append((url, depth))

                    results = await asyncio.gather(*(crawl_one(u) for u, _ in urls))
                    next_level = []
                    for (url, depth), (page, soup) in zip(urls, results):
                        if page is None:
                            continue
                        pages.append(page)
                        all_headers[page["url"]] = page["headers"]
                        await context.emit_agent(
                            "recon", f"GET {page['url']} -> {page['status']}"
                        )
                        if page["status"] >= 400 or not soup or depth >= max_depth:
                            continue
                        forms.extend(_extract_forms(soup, page["url"]))
                        for meta in soup.find_all("meta", attrs={"name": True}):
                            if meta.get("name", "").lower() == "generator" and meta.get("content"):
                                meta_generators.append(meta["content"])
                        for link in soup.find_all("a", href=True):
                            href = urljoin(page["url"], link["href"])
                            parsed = urlsplit(href)
                            if parsed.scheme in ("http", "https") and parsed.netloc == host:
                                next_level.append((href, depth + 1))

                    level = next_level

                visited_all.extend(sorted(visited))

        tech = _detect_tech(all_headers.get(base if targets else "", {}), meta_generators)
        context.results[self.name] = {
            "pages": pages,
            "urls": sorted(set(visited_all)),
            "forms": forms,
            "headers": all_headers,
            "tech_stack": tech,
        }
        if not pages:
            context.connection_issues.append(
                f"could not reach {context.url} — the site may be down or blocking the scanner"
            )
        await context.emit_agent(
            self.name,
            f"recon complete: {len(pages)} page(s), {len(forms)} form(s), "
            f"tech: {', '.join(tech) if tech else 'unknown'}",
        )


async def _fetch(client, url):
    try:
        return await client.get(url)
    except httpx.TransportError:
        alt = (
            url.replace("https://", "http://", 1)
            if url.startswith("https://")
            else url.replace("http://", "https://", 1)
        )
        try:
            return await client.get(alt)
        except httpx.TransportError:
            return None


def _normalize(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


async def _load_robots(base, host):
    try:
        async with httpx.AsyncClient(timeout=8.0, headers={"User-Agent": USER_AGENT}) as client:
            resp = await client.get(f"{urlsplit(base).scheme}://{host}/robots.txt")
            if resp.status_code != 200:
                return None
            rp = RobotFileParser()
            rp.parse(resp.text.splitlines())
            return rp
    except (httpx.HTTPError, httpx.TimeoutException):
        return None


def _extract_forms(soup, page_url):
    out = []
    for form in soup.find_all("form"):
        action = urljoin(page_url, form.get("action", page_url))
        method = form.get("method", "get").lower()
        inputs = []
        for inp in form.find_all("input"):
            name = inp.get("name")
            if name:
                inputs.append({"name": name, "type": inp.get("type", "text")})
        out.append({"action": action, "method": method, "inputs": inputs})
    return out


def _detect_tech(headers, meta_generators):
    tech = []
    for name in ("server", "x-powered-by", "x-aspnet-version"):
        val = headers.get(name)
        if val:
            tech.append(f"{name}: {val}")
    header_blob = " ".join(f"{key}: {val}" for key, val in headers.items())
    body_blob = " ".join(meta_generators)
    for sig, label in TECH_SIGNATURES:
        if sig.search(header_blob) or sig.search(body_blob):
            tech.append(label)
    return sorted(set(tech))