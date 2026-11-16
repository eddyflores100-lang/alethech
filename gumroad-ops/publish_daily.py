#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""publish_daily — el lote diario de Gumroad, ejecutado por GitHub Actions.

Cuota rodante 24h (tope 10/24h) + inventario preparado (gumroad-ops/packs/).
Publica hasta llenar los cupos libres, verifica cada producto y deja el estado
en gumroad-ops/state/ (el workflow lo commitea para la siguiente corrida).

Solo stdlib (urllib). Token por env GUMROAD_TOKEN (secret del repo).
Uso: python3 gumroad-ops/publish_daily.py [--dry-run]
Contrato de packs: gumroad-ops/packs/README.md
"""
import base64
import glob
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

REPO = 'eddyflores100-lang/alethech'
BASE = os.path.dirname(os.path.abspath(__file__))
API = 'https://api.gumroad.com/v2'
STORE = 'https://alicelabs.gumroad.com/l'
RAW = f'https://raw.githubusercontent.com/{REPO}/main/gumroad-ops'
TOKEN = os.environ['GUMROAD_TOKEN']
MAX_DIA = 10


def api(method, path, headers=None, fields=None, data=None):
    url = API + path
    req = urllib.request.Request(url, method=method)
    req.add_header('Authorization', f'Bearer {TOKEN}')
    body = None
    if fields is not None:
        import uuid
        boundary = uuid.uuid4().hex
        parts = []
        for k, v in fields:
            parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
        parts.append(f'--{boundary}--\r\n'.encode())
        body = b''.join(parts)
        req.add_header('Content-Type', f'multipart/form-data; boundary={boundary}')
    elif data is not None:
        body = data
        req.add_header('Content-Type', headers.get('Content-Type', 'application/x-www-form-urlencoded'))
    for k, v in (headers or {}).items():
        if k != 'Content-Type' or fields is None:
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, data=body, timeout=60) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {}


def esc(s):
    import html
    return html.escape(str(s))


def desc_html(spec):
    files = ''.join(f'<li>{esc(f)} — {esc(d)}</li>' for f, d in spec['files'])
    return (
        f'<p><b>{esc(spec["name"].split(" — ")[0])}</b>. {esc(spec["pain"])} '
        f'This kit is the fix on paper: a playbook with process diagrams, calculators built on your own '
        f'numbers, and templates where every [bracketed] field is yours to replace.</p>'
        f'<p><b>Where it works:</b> {esc(spec["geo"])}. Templates are editable; the playbook names what to '
        f'verify locally before you rely on anything.</p>'
        f'<p><b>What you get</b></p><ul>{files}</ul>'
        f'<p><b>Who it is for:</b> owners and operators who are done improvising. Part of the AliceLabs '
        f'series, <a href="https://alicelabs.gumroad.com/">gumroad.com/alicelabs</a>.</p>'
        f'<p><b>Search terms:</b> {esc(spec["kw"])}</p>'
        f'<p>One honest note: this is business process material, not legal, tax or financial advice. Rules '
        f'change by jurisdiction and year - the playbook names what to verify.</p>')


def rich_page(spec):
    def H(lv, t):
        return {'type': 'heading', 'attrs': {'level': lv}, 'content': [{'type': 'text', 'text': t}]}
    def P(t):
        return {'type': 'paragraph', 'content': [{'type': 'text', 'text': t}]}
    def LI(t):
        return {'type': 'list_item', 'content': [{'type': 'paragraph', 'content': [{'type': 'text', 'text': t}]}]}
    pain_first = spec['pain'].split('.')[0]
    d = {'type': 'doc', 'content': [
        H(2, f'Start here — {spec["name"].split(" — ")[0]}'),
        P(f'Thanks for picking this up. Short version: {pain_first}. The playbook fixes it with process '
          'and paperwork, in that order.'),
        H(3, 'What you downloaded'),
        {'type': 'bullet_list', 'content': [LI(f'{f} — {d2}') for f, d2 in spec['files']]},
        H(3, 'How to run it'),
        {'type': 'ordered_list', 'content': [
            LI('Open the pain map at the front of Playbook.pdf and pick your two rows.'),
            LI('Read Playbook.pdf once, end to end. Half an hour, diagrams included.'),
            LI('Open the calculator(s) and swap every sample number for yours. Ten minutes.'),
            LI('Edit the templates and replace every [bracketed] field before anything leaves your office.'),
            LI('Run the rollout plan at the back of the playbook, then re-check weekly.'),
        ]},
        H(3, 'Support'),
        P('Reply to your Gumroad receipt email and a human gets back to you. Updates included. More kits '
          'at gumroad.com/alicelabs.'),
    ]}
    return [{'title': 'Start here', 'description': d}]


def upload_blob(path, filename, filetype):
    size = os.path.getsize(path)
    st, pr = api('POST', '/files/presign', fields=[('filename', filename), ('file_size', str(size)),
                                                  ('filetype', filetype)])
    if st != 200 or not pr.get('success'):
        raise RuntimeError(f'presign: {str(pr)[:150]}')
    etags = []
    for part in pr['parts']:
        put = subprocess.run(['curl', '-s', '-X', 'PUT', '-o', '/dev/null', '-w', '%{header_json}',
                              '--upload-file', path, part['presigned_url']],
                             capture_output=True, text=True).stdout
        etag = json.loads(put).get('etag', [''])[0].strip('"')
        etags.append((part['part_number'], etag))
    fields = [('upload_id', pr['upload_id']), ('key', pr['key'])]
    for pn, et in etags:
        fields.append((f'parts[][part_number]', str(pn)))
        fields.append((f'parts[][etag]', et))
    st, comp = api('POST', '/files/complete', fields=fields)
    if st != 200 or not comp.get('success'):
        raise RuntimeError(f'complete: {str(comp)[:150]}')
    return comp['file_url']


def web_ok(slug):
    code = subprocess.run(['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '30',
                           f'{STORE}/{slug}'], capture_output=True, text=True).stdout.strip()
    return code == '200', code


def verify(pid, spec):
    st, d = api('GET', f'/products/{pid}')
    pd = d.get('product', d)
    files = pd.get('files', [])
    rc = pd.get('rich_content') or []
    lens = [len(json.dumps(x.get('description', {}), ensure_ascii=False)) for x in rc]
    wok, code = web_ok(spec['slug'])
    ok = (pd.get('published') and pd.get('price') == spec['price'] * 100 and len(files) == 1
          and len(pd.get('covers') or []) >= 1 and bool(pd.get('thumbnail_url'))
          and rc and all(l > 1000 for l in lens) and len(pd.get('tags') or []) == 5
          and (pd.get('custom_permalink') or '') == spec['slug'] and wok)
    if not ok and not pd.get('published'):
        api('PATCH', f'/products/{pid}', fields=[('published', 'true')])
        time.sleep(3)
        st, d = api('GET', f'/products/{pid}')
        pd = d.get('product', d)
        ok = (pd.get('published') and len(pd.get('covers') or []) >= 1
              and bool(pd.get('thumbnail_url')) and wok)
    print(f'   verify: pub={pd.get("published")} price={pd.get("price")} files={len(files)} '
          f'cov={len(pd.get("covers") or [])} thumb={bool(pd.get("thumbnail_url"))} rc={lens} '
          f'tags={len(pd.get("tags") or [])} web={code}', flush=True)
    return ok


def cupos_libres(state_dir):
    log_path = os.path.join(state_dir, 'creaciones_log.json')
    try:
        entradas = json.load(open(log_path))
    except Exception:
        entradas = []
    ahora = datetime.now(timezone.utc)
    ventana = 0
    for e in entradas:
        try:
            if ahora - datetime.fromisoformat(e) < timedelta(hours=24):
                ventana += 1
        except Exception:
            pass
    return max(0, MAX_DIA - ventana), entradas


def log_creacion(state_dir, entradas):
    entradas.append(datetime.now(timezone.utc).isoformat())
    json.dump(entradas, open(os.path.join(state_dir, 'creaciones_log.json'), 'w'), indent=1)


def slugs_vivos():
    vivos, key = set(), None
    while True:
        q = '?page_key=' + urllib.parse.quote(key) if key else ''
        req = urllib.request.Request(f'{API}/products{q}')
        req.add_header('Authorization', f'Bearer {TOKEN}')
        with urllib.request.urlopen(req, timeout=30) as r:
            resp = json.loads(r.read())
        for p in resp.get('products', []):
            vivos.add(p.get('custom_permalink') or '')
        key = resp.get('next_page_key')
        if not key:
            break
    return vivos


def publish_one(spec, pack_dir, state_dir, entradas):
    slug = spec['slug']
    zpath = os.path.join(pack_dir, spec['zip'])
    if not os.path.exists(zpath):
        print(f'!! {slug}: sin zip en el pack', flush=True)
        return 'fail'
    st, d = api('POST', '/products', fields=[('name', spec['name']),
                                             ('price', str(spec['price'] * 100)),
                                             ('currency', 'usd')])
    if not d.get('product'):
        msg = d.get('message') or str(d)[:150]
        print(f'!! {slug} create: {msg[:110]}', flush=True)
        return 'quota' if '10 products per day' in msg else 'fail'
    pid = d['product']['id']
    log_creacion(state_dir, entradas)
    print(f'CREATE {slug:34s} pid={pid[:12]} price=${spec["price"]}', flush=True)
    time.sleep(5)
    api('PATCH', f'/products/{pid}', fields=[('custom_permalink', slug)])
    time.sleep(3)
    open('/tmp/desc.html', 'w').write(desc_html(spec))
    subprocess.run(['curl', '-s', '-X', 'PATCH', '-H', f'Authorization: Bearer {TOKEN}',
                    '--data-urlencode', 'description@/tmp/desc.html', f'{API}/products/{pid}'],
                   capture_output=True)
    time.sleep(4)
    furl = upload_blob(zpath, spec['zipname'], 'application/zip')
    api('PATCH', f'/products/{pid}', fields=[('files[][url]', furl), ('files[][name]', spec['zipname'])])
    time.sleep(6)
    body = json.dumps({'rich_content': rich_page(spec)}).encode()
    api('PATCH', f'/products/{pid}', headers={'Content-Type': 'application/json'}, data=body)
    time.sleep(5)
    api('PATCH', f'/products/{pid}', fields=[('tags[]', t) for t in spec['tags']])
    time.sleep(4)
    for fname, kind in ((spec['cover_png'], 'covers'), (spec['sq_png'], 'thumbnail')):
        raw = f'{RAW}/{os.path.relpath(os.path.join(pack_dir, fname), BASE)}'
        api('POST', f'/products/{pid}/{kind}', data=urllib.parse.urlencode({'url': raw}).encode())
        time.sleep(4)
    ok = verify(pid, spec)
    print(f'{"OK  " if ok else "FALLO"} {slug}', flush=True)
    return 'ok' if ok else 'fail'


def main():
    dry = '--dry-run' in sys.argv
    state_dir = os.path.join(BASE, 'state')
    libres, entradas = cupos_libres(state_dir)
    vivos = slugs_vivos()
    pendientes = []
    for meta_path in sorted(glob.glob(os.path.join(BASE, 'packs', '*', 'meta.json'))):
        pack_dir = os.path.dirname(meta_path)
        st_path = os.path.join(state_dir, 'published_state.json')
        try:
            pst = json.load(open(st_path))
        except Exception:
            pst = {}
        for spec in json.load(open(meta_path)):
            rel_zip = os.path.join(os.path.basename(pack_dir), spec['zip'])
            if (spec['slug'] not in vivos and pst.get(spec['slug']) != 'ok'
                    and os.path.exists(os.path.join(pack_dir, spec['zip']))):
                pendientes.append((pack_dir, spec))
    print(f'CUOTA: {libres}/10 libres | INVENTARIO PREPARADO: {len(pendientes)} por publicar', flush=True)
    if dry:
        for _, s in pendientes[:libres]:
            print(f'  - {s["slug"]} (${s["price"]})')
        return
    hechos, fallos = 0, []
    for pack_dir, spec in pendientes:
        if libres <= 0:
            break
        r = publish_one(spec, pack_dir, state_dir, entradas)
        if r == 'quota':
            print('CUOTA AGOTADA — parando.', flush=True)
            break
        if r == 'ok':
            hechos += 1
            libres -= 1
            pst_path = os.path.join(state_dir, 'published_state.json')
            pst = json.load(open(pst_path))
            pst[spec['slug']] = 'ok'
            json.dump(pst, open(pst_path, 'w'), indent=1)
        else:
            fallos.append(spec['slug'])
        time.sleep(8)
    restante = len(pendientes) - hechos
    resumen = (f'Lote diario Gumroad: {hechos} publicados y verificados. '
               f'Inventario preparado restante: {max(0, restante)} (siguiente corrida lo toma). '
               f'Cupos 24h: {libres} libres tras la corrida.'
               + (f' FALLOS: {", ".join(fallos)}' if fallos else ''))
    print(resumen, flush=True)
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        open(summary, 'a').write(f'## Gumroad diario\n\n{resumen}\n')
    if fallos:
        sys.exit(1)


if __name__ == '__main__':
    main()
