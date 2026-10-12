"""Public download links must resolve to committed artifacts."""
from html.parser import HTMLParser
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]


class Downloads(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and attrs.get("href", "").startswith("downloads/"):
            self.links.append(attrs["href"])


@pytest.mark.parametrize("page", ["index.html", "landing.html", "capture.html"])
def test_public_downloads_exist(page):
    parser = Downloads()
    parser.feed((ROOT / page).read_text(encoding="utf-8"))
    assert parser.links, "page must expose a download"
    for href in parser.links:
        assert (ROOT / href).is_file(), f"{page} advertises missing download {href}"
