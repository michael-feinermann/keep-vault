import hashlib, json, pathlib, urllib.request, unicodedata, concurrent.futures

OUT = pathlib.Path('KalynaArchiver/Resources/PasswordModel')
ZX = '642ef8f0c40d8267e9fc2d4de29ab2691e87a10e'
DB = '67c4ece9efc40c9d0a1d7d995b2b22a91be500c2'
DE = '6ef31b9aefb8735a7b066592393d12843ec502cd'
BI = '09e21036a4001fe6c9ba65c1d3a39b737768132f'
TR = 'b57a5ad77a981e743f4167ab2f7927a55c1e82a8'
raw = lambda repo, rev, path: f'https://raw.githubusercontent.com/{repo}/{rev}/{path}'
specs = [
 ('eff-en.txt', 'list', 'en', 7776, 'https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt', 'CC-BY-4.0', 'dice'),
 ('diceware-de.txt', 'list', 'de', 7776, raw('dys2p/wordlists-de',DE,'de-7776-v1.txt'), 'CC0-1.0', 'lines'),
 ('bip39-en.txt', 'bip39', 'en', 2048, raw('bitcoin/bips',BI,'bip-0039/english.txt'), 'MIT', 'lines'),
 ('rank-de.txt', 'rank', 'de', None, raw('zxcvbn-ts/zxcvbn',ZX,'packages/languages/de/src/commonWords.json'), 'ODC-BY-1.0', 'json'),
 ('rank-en.txt', 'rank', 'en', None, raw('zxcvbn-ts/zxcvbn',ZX,'packages/languages/en/src/commonWords.json'), 'ODC-BY-1.0', 'json'),
 ('names-de.txt', 'names', 'de', None, raw('zxcvbn-ts/zxcvbn',ZX,'packages/languages/de/src/firstnames.json'), 'MIT', 'json'),
 ('names-en-female.txt', 'names', 'en', None, raw('dropbox/zxcvbn',DB,'data/female_names.txt'), 'MIT', 'lines'),
 ('names-en-male.txt', 'names', 'en', None, raw('dropbox/zxcvbn',DB,'data/male_names.txt'), 'MIT', 'lines'),
 ('passwords.txt', 'blocklist', 'und', None, raw('dropbox/zxcvbn',DB,'data/passwords.txt'), 'MIT', 'passwords'),
]

def get(spec):
 name,kind,lang,expected,url,license,parser=spec
 source=urllib.request.urlopen(url,timeout=30).read()
 text=source.decode('utf-8-sig')
 values=json.loads(text) if parser=='json' else text.splitlines()
 if parser=='dice':
  assert len(values)==7776
  assert len({v.split()[0] for v in values})==7776
  values=[v.split()[1] for v in values]
 elif parser=='passwords': values=[v.rsplit(None,1)[0].strip() for v in values][:30000]
 sourcecount=len(values)
 # Analysis dictionary entries only. Rank order retained; first normalized duplicate wins.
 seen=set(); entries=[]; duplicates=0
 for value in values:
  assert isinstance(value,str) and value and not any(c in value for c in '\r\n\t')
  normalized=unicodedata.normalize('NFC',value).lower()
  assert normalized
  if normalized in seen: duplicates+=1; continue
  seen.add(normalized); entries.append(normalized)
 if expected is not None: assert len(entries)==expected and duplicates==0
 output=('\n'.join(entries)+'\n').encode('utf-8')
 (OUT/name).write_bytes(output)
 return dict(file=name,kind=kind,language=lang,count=len(entries),sha256=hashlib.sha256(output).hexdigest(),source=url,sourceSha256=hashlib.sha256(source).hexdigest(),sourceEntries=sourcecount,normalizationDuplicates=duplicates,license=license,transform='UTF-8 NFC lowercase, unique first occurrence, LF; '+parser,normalizationCollisionPolicy='retain cheapest matching analysis form at runtime; original list/count/order unchanged')

OUT.mkdir(parents=True,exist_ok=True)
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool: files=list(pool.map(get,specs))

# A finite, explicitly curated attack dictionary. Order is a declared enumeration, not measured frequency.
phrases=[
 'correct horse battery staple','to be or not to be','may the force be with you',
 'the quick brown fox jumps over the lazy dog','all you need is love',
 'ich liebe dich','ich liebe dich für immer','das leben ist schön',
 'morgenstund hat gold im mund','wer rastet der rostet','sein oder nicht sein',
 'winter spring summer autumn','frühling sommer herbst winter',
 'january february march april may june july august september october november december',
 'januar februar märz april mai juni juli august september oktober november dezember',
]
curated=['correcthorsebatterystaple','correct horse battery staple','abandon '*11+'about', 'legal winner thank year wave sausage worth useful legal winner thank yellow', 'letter advice cage absurd amount doctor acoustic avoid letter advice cage above', 'zoo '*11+'wrong']
for name,kind,entries in [('phrases.txt','phrases',phrases),('curated-blocklist.txt','blocklist',curated)]:
 b=('\n'.join(entries)+'\n').encode();(OUT/name).write_bytes(b)
 files.append(dict(file=name,kind=kind,language='en-de',count=len(entries),sha256=hashlib.sha256(b).hexdigest(),source='Keep Vault 5.0.2 finite public-example enumeration; README.md',sourceSha256=hashlib.sha256(b).hexdigest(),sourceEntries=len(entries),normalizationDuplicates=0,license='MIT',transform='local authored enumeration, UTF-8 NFC lowercase LF',normalizationCollisionPolicy='exact line entries; variants are analysis only'))
licenses={
 'LICENSE-zxcvbn.txt':raw('dropbox/zxcvbn',DB,'LICENSE.txt'),
 'LICENSE-zxcvbn-ts.txt':raw('zxcvbn-ts/zxcvbn',ZX,'LICENSE.txt'),
 'NOTICE-OPUS-de.md':raw('zxcvbn-ts/zxcvbn',ZX,'packages/languages/de/NOTICE.md'),
 'NOTICE-OPUS-en.md':raw('zxcvbn-ts/zxcvbn',ZX,'packages/languages/en/NOTICE.md'),
 'LICENSE-ODC-BY.txt':'https://raw.githubusercontent.com/spdx/license-list-data/3ac5a9c241d97f95b22a5e366c9c841404a35639/text/ODC-By-1.0.txt',
 'LICENSE-CC-BY-4.0.txt':'https://raw.githubusercontent.com/spdx/license-list-data/3ac5a9c241d97f95b22a5e366c9c841404a35639/text/CC-BY-4.0.txt',
 'LICENSE-CC0-1.0.txt':'https://raw.githubusercontent.com/spdx/license-list-data/3ac5a9c241d97f95b22a5e366c9c841404a35639/text/CC0-1.0.txt',
 'LICENSE-bip39.txt':raw('trezor/python-mnemonic',TR,'LICENSE'),
 'LICENSE-dys2p.txt':raw('dys2p/wordlists-de',DE,'LICENSE'),
}
for name,url in licenses.items():(OUT/name).write_bytes(urllib.request.urlopen(url,timeout=30).read())
licenses['LICENSE-curated-lists.txt']='https://github.com/michael-feinermann/keep-vault/blob/codex/keep-vault-5.0.2/KalynaArchiver/Resources/PasswordModel/LICENSE-curated-lists.txt'
assert (OUT/'LICENSE-curated-lists.txt').is_file() # Locally authored scoped license is retained, not fetched.
manifest={'version':'keep-vault-password-model-2026-09-06-v1','schema':1,'retrievedUtc':'2026-09-06','referenceYear':2026,'calibration':'No empirical calibration or entropy claim; finite search families and inherited conservative score.','blocklistCoverage':'First 30000 public aggregated zxcvbn password candidates plus six public examples. Not HIBP, not a complete breach corpus. Exact whole-input comparison, no dictionary-word ban.','files':files}
mirror=raw('trezor/python-mnemonic',TR,'src/mnemonic/wordlist/english.txt')
mirrorbytes=urllib.request.urlopen(mirror,timeout=30).read()
assert mirrorbytes==(OUT/'bip39-en.txt').read_bytes()
manifest['bip39LicensedMirror']={'source':mirror,'sha256':hashlib.sha256(mirrorbytes).hexdigest(),'licenseSource':licenses['LICENSE-bip39.txt'],'byteIdenticalToCanonicalBitcoinBips':True}
manifest['licenseFiles']=[{'file':name,'sha256':hashlib.sha256((OUT/name).read_bytes()).hexdigest(),'source':url} for name,url in sorted(licenses.items())]
(OUT/'manifest.json').write_text(json.dumps(manifest,indent=2,ensure_ascii=False)+'\n')
for f in files:print(f['file'], f['count'], f['sha256'], 'duplicates',f['normalizationDuplicates'])
print('manifest_sha256',hashlib.sha256((OUT/'manifest.json').read_bytes()).hexdigest())
