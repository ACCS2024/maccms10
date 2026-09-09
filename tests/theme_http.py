#!/usr/bin/env python3
"""Read-only HTTP checks for the isolated, real-data theme preview."""
import argparse
import json
import re
from html.parser import HTMLParser
from urllib.error import HTTPError
from urllib.parse import urlencode, urljoin
from urllib.request import Request, urlopen


class Page(HTMLParser):
    def __init__(self, markup):
        super().__init__()
        self.links = []
        self.inputs = {}
        self.resource_urls = []
        self.resource_names = []
        self._resource = False
        self.feed(markup)

    def handle_starttag(self, tag, pairs):
        attrs = dict(pairs)
        if tag == 'a':
            self.links.append(attrs)
            self._resource = 'resource-title' in attrs.get('class', '').split()
            if self._resource:
                self.resource_urls.append(attrs.get('href', ''))
                self.resource_names.append('')
        if tag == 'input' and attrs.get('name'):
            self.inputs[attrs['name']] = attrs.get('value', '')

    def handle_endtag(self, tag):
        if tag == 'a':
            self._resource = False

    def handle_data(self, text):
        if self._resource:
            self.resource_names[-1] += text


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base', required=True)
    parser.add_argument('--output', default='/tmp/maccms-theme-v2-http.json')
    args = parser.parse_args()
    assert '/theme-preview-' in args.base, 'Use the isolated preview entry.'
    results = []

    def fetch(name, href='', expected_rows=None, marker='assets/v2/theme.css'):
        url = urljoin(args.base, href) if href else args.base
        with urlopen(url, timeout=60) as response:
            assert response.status == 200, name
            body = response.read().decode('utf-8')
            assert 'no-store' in response.headers.get('Cache-Control', ''), name
            assert 'noindex' in response.headers.get('X-Robots-Tag', ''), name
        assert marker in body, name + ': expected theme marker missing'
        assert not re.search(r'\{(?:maccms:|include |\$)', body), name + ': raw template tags'
        parsed = Page(body)
        if expected_rows is not None:
            assert len(parsed.resource_urls) == expected_rows, (name, len(parsed.resource_urls))
        results.append({'page': name, 'status': 200, 'rows': len(parsed.resource_urls)})
        return body, parsed

    _, home = fetch('home', expected_rows=70)
    next_page = next(a['href'] for a in home.links if a.get('rel') == 'next')
    _, page2 = fetch('home_page_2', next_page, 70)
    assert home.resource_urls[0] != page2.resource_urls[0], 'Pagination repeated first page'
    vod_types = list(dict.fromkeys(a['href'] for a in home.links if 'vodtype/' in a.get('href', '')))
    fetch('parent_category', vod_types[0], 40)
    fetch('child_category', vod_types[1], 40)
    art_type = next(a['href'] for a in home.links if 'arttype/' in a.get('href', ''))
    _, art = fetch('article_category', art_type, 40)
    fetch('article_detail', art.resource_urls[0], marker='class="article-content"')
    _, detail = fetch('video_detail', home.resource_urls[0], marker='data-address-group')
    play = next(a['href'] for a in detail.links if 'vodplay/' in a.get('href', ''))
    fetch('play_shell', play, marker='player-stage')
    # Query parameters must reset a page encoded in the URL when changing order.
    asc = args.base + '/index.html?order=asc&by=time&page=1'
    _, first = fetch('ascending_order', asc, 70)
    _, reset = fetch('sort_resets_page', urljoin(args.base, next_page) + '?order=asc&by=time&page=1', 70)
    assert first.resource_urls[0] == reset.resource_urls[0], 'Sorting failed to reset page'
    search = args.base + '/vodsearch.html?'
    fetch('empty_search', search + urlencode({'wd': 'zz_theme_no_match_938271'}), 0)
    _, special = fetch('escaped_search', search + urlencode({'wd': 'Audit & Review'}), 0)
    assert special.inputs.get('wd') == 'Audit & Review', 'Search term double escaped'
    _, positive = fetch('matching_search', search + urlencode({'wd': home.resource_names[0][:16]}))
    assert positive.resource_urls, 'Exact title search did not return any resources'
    for name, suffix, expected in [('missing_resource', '/voddetail/999999999.html', 404), ('disallowed_route', '/admin/index.html', 404)]:
        try:
            urlopen(args.base + suffix, timeout=60)
            raise AssertionError(name + ': expected error status')
        except HTTPError as error:
            assert error.code == expected, (name, error.code)
        results.append({'page': name, 'status': expected})
    try:
        urlopen(Request(args.base, data=b'', method='POST'), timeout=30)
        raise AssertionError('Preview accepted POST')
    except HTTPError as error:
        assert error.code == 405
    results.append({'page': 'preview_post_block', 'status': 405})
    with open(args.output, 'w') as handle:
        json.dump(results, handle, indent=2)
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
