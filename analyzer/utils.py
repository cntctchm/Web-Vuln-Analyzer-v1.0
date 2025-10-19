from urllib.parse import urlparse, urljoin

def normalize_url(url: str) -> str:
    url = url.strip()
    if not url:
        return url
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url

def safe_join(base: str, link: str) -> str:
    if not link:
        return ""
    return urljoin(base, link)

def domain_from_url(url: str) -> str:
    try:
        return urlparse(url).netloc
    except:
        return url
