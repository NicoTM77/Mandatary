#!/usr/bin/env python3
"""Offline reproduction of the approved NFC17 snapshot; Python stdlib only.

Inputs are byte-checked before extraction. Apply a reviewed exact diff;
this script does not implement normalization or trust compiler Unicode tables.
"""
import argparse

import gzip
import hashlib
import json
import pathlib
import re
import subprocess


ROOT = pathlib.Path(__file__).resolve().parents[1]
BASE = ROOT / 'internal/auth/nfc17'
RANGES = {
 'normalize.go': [(1,4),(44,56),(182,189),(251,257),(300,355),(501,555)],
 'composition.go': [(1,112),(133,156),(181,228),(246,275),(277,332),(334,378),(380,384),(408,524)],
 'forminfo.go': [(1,60),(90,228),(250,296)],
 'input.go': [(1,25),(32,48),(61,83),(92,109)],
}

def digest(b):
    return hashlib.sha256(b).hexdigest()

def apply_adaptation(files):
    # Exact unified-diff application, no patch executable, fuzzy match or offsets.
    # Only the already authenticated six source basenames may be addressed.
    lines = (BASE/'adaptation.patch').read_text().splitlines(True)
    index = 0
    while index < len(lines):
        if not lines[index].startswith('--- a/'):
            raise ValueError('adaptation header')
        name = lines[index][6:].strip()
        index += 1
        if name not in files or lines[index] != '+++ b/'+name+'\n':
            raise ValueError('adaptation target')
        index += 1
        old = files[name].decode().splitlines(True)
        result = []
        cursor = 0
        while index < len(lines) and lines[index].startswith('@@ '):
            hunk = re.fullmatch(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@\n', lines[index])
            if hunk is None:
                raise ValueError('adaptation hunk schema')
            start = int(hunk[1]) - (1 if int(hunk[2] or '1') else 0)
            if start < cursor:
                raise ValueError('adaptation overlap')
            result.extend(old[cursor:start])
            cursor = start
            consumed = produced = 0
            index += 1
            while index < len(lines) and not lines[index].startswith(('@@ ', '--- a/')):
                line = lines[index]
                if line[0] in (' ', '-'):
                    if cursor >= len(old) or old[cursor] != line[1:]:
                        raise ValueError('adaptation context differs: '+name)
                    cursor += 1
                    consumed += 1
                if line[0] in (' ', '+'):
                    result.append(line[1:])
                    produced += 1
                if line[0] not in (' ', '-', '+'):
                    raise ValueError('adaptation line schema')
                index += 1
            if consumed != int(hunk[2] or '1') or produced != int(hunk[4] or '1'):
                raise ValueError('adaptation hunk count')
        result.extend(old[cursor:])
        files[name] = ''.join(result).encode()
    return files

def sources(upstream):
    expected = json.loads((BASE/'upstream-sha256.json').read_text())
    result = {}
    for name, sha in expected.items():
        raw = (upstream/name).read_bytes()
        if digest(raw) != sha:
            raise ValueError('upstream input checksum: '+name)
        if name not in RANGES:
            text = raw.decode()
        else:
            lines = raw.decode().splitlines(True)
            chunks = [''.join(lines[a-1:b]) for a,b in RANGES[name]]
            if name == 'normalize.go':
                chunks.insert(1, '\npackage nfc17\n\ntype Form int\nconst NFC Form = 0\n\n')
            if name == 'forminfo.go':
                chunks.insert(1, '\n}\nvar formTable = []*formInfo{{composing:true, info:lookupInfoNFC}}\n')
            text = ''.join(chunks)
        text = re.sub(r'//go:build[^\n]*\n', '', text)
        text = text.replace('package norm // import "golang.org/x/text/unicode/norm"','package nfc17').replace('package norm','package nfc17')
        target = 'tables.go' if name == 'tables17.0.0.go' else name
        result[target] = subprocess.run(['gofmt'], input=text.encode(), stdout=subprocess.PIPE, check=True).stdout
    return result

def repertoire():
    manifest = json.loads((BASE/'data-sha256.json').read_text())
    for name, spec in manifest.items():
        b = (BASE/name).read_bytes() if name.startswith('LICENSE') else gzip.decompress((BASE/'testdata'/(name+'.gz')).read_bytes())
        if digest(b) != spec['sha256'] or len(b) != spec['bytes']:
            raise ValueError('Unicode input checksum: '+name)
    data = gzip.decompress((BASE/'testdata/DerivedGeneralCategory.txt.gz').read_bytes()).decode()
    ranges = []
    for line in data.splitlines():
        line = line.split('#')[0].strip()
        if not line:
            continue
        span, cat = map(str.strip, line.split(';'))
        if cat in ('Cn','Cs'):
            continue
        ends = span.split('..')
        ranges.append((int(ends[0],16),int(ends[-1],16)))
    merged = []
    for a,b in sorted(ranges):
        if merged and merged[-1][1]+1 == a:
            merged[-1] = (merged[-1][0],b)
        else:
            merged.append((a,b))
    text = '// Code generated from frozen Unicode17 DerivedGeneralCategory; DO NOT EDIT.\npackage nfc17\n\nvar assignedRanges = [...][2]rune{\n'+''.join('{0x%x,0x%x},\n' % (a,b) for a,b in merged)+'}\n'
    return subprocess.run(['gofmt'],input=text.encode(),stdout=subprocess.PIPE,check=True).stdout

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream',required=True,type=pathlib.Path,help='verified x/text v0.43.0 unicode/norm directory')
    parser.add_argument('--check',action='store_true',help='compare without repairing committed output')
    args = parser.parse_args()
    spec = json.loads((BASE/'snapshot.json').read_text())
    if digest((BASE/'adaptation.patch').read_bytes()) != spec['adaptation_sha256']:
        raise ValueError('adaptation checksum')
    files = sources(args.upstream)
    files = apply_adaptation(files)
    for name,sha in spec['adapted_sha256'].items():
        if digest(files[name]) != sha:
            raise ValueError('adapted source checksum: '+name)
    files['repertoire_data.go'] = repertoire()
    files['LICENSE-GO'] = (args.upstream.parents[1]/'LICENSE').read_bytes()
    if digest(files['LICENSE-GO']) != spec['license_sha256']:
        raise ValueError('Go license checksum')
    failed = []
    for name,b in files.items():
        if args.check:
            if (BASE/name).read_bytes()!=b:
                failed.append(name)
        else:
            (BASE/name).write_bytes(b)
    if failed:
        raise SystemExit('generated output differs: '+','.join(failed))
    print('frozen source/data integrity and reproduction: '+str(len(files))+' files OK')

if __name__ == '__main__':
    main()
