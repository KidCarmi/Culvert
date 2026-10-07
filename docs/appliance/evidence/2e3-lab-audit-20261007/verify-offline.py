import pathlib,hashlib,tarfile,io,json,gzip,collections,csv,subprocess
root=pathlib.Path(__file__).resolve().parent
path=root/'artifact-11475570320/culvert-image.tar'
sha=lambda b:hashlib.sha256(b).hexdigest()
with path.open('rb') as f: tarsha=hashlib.file_digest(f,'sha256').hexdigest()
assert tarsha=='db4f5ce8784e2a8e5145fdf59126a8e675a27f6628ac3b70e0d2ac16daf5ffff'
with tarfile.open(path) as archive:
 def blob(digest):
  b=archive.extractfile('blobs/sha256/'+digest.split(':')[1]).read();assert 'sha256:'+sha(b)==digest;return b
 index=json.load(archive.extractfile('index.json'))
 desc=index['manifests'][0]; manifest=json.loads(blob(desc['digest']))
 assert desc['digest']=='sha256:536403fc9ba8a4bc15d229a12a7586ce6ccc35ba99148b71869a81596e0ea940'
 cfg=manifest['config']['digest'];config=json.loads(blob(cfg))
 assert cfg=='sha256:7b3c98273c372b2875c140d4c678f415f3dda681e185e290c6b9b7234e1f1714'
 binaries={}; wanted={'app/culvert':'culvert','app/deploy/bin/culvert-maint':'culvert-maint','app/VERSION':'VERSION'}
 (root/'private-binaries').mkdir(exist_ok=True)
 for i,layer in enumerate(manifest['layers']):
  data=blob(layer['digest']);raw=gzip.decompress(data) if data[:2]==b'\x1f\x8b' else data
  assert 'sha256:'+sha(raw)==config['rootfs']['diff_ids'][i]
  with tarfile.open(fileobj=io.BytesIO(raw)) as files:
   for item in files:
    name=item.name.removeprefix('./')
    if name in wanted and item.isfile():
     b=files.extractfile(item).read();(root/'private-binaries'/wanted[name]).write_bytes(b)
     binaries[name]={'sha256':sha(b),'size':len(b)}
 evidence={'tar_sha256':tarsha,'manifest_digest':desc['digest'],'config_image_id':cfg,'layers_verified':len(manifest['layers']),'uncompressed_diff_ids_verified':len(config['rootfs']['diff_ids']),'os':config['os'],'architecture':config['architecture'],'binaries':binaries}
 evidence['version']=(root/'private-binaries/VERSION').read_text().strip()
q=root/'artifact-11477120696';fd=root/'artifact-11474899905'
counts={}
for label,p in [('qemu',q),('fdisk',fd)]:
 rows=[json.loads(s) for s in (p/'checks.jsonl').read_text().splitlines() if s.strip()]
 counts[label]=dict(collections.Counter(r['result'] for r in rows));assert not any(r['result']=='fail' for r in rows)
trials=[]
for i in [1,2,3]:
 t=json.loads((q/f'R-esxi12-{i}-timeline.json').read_text())
 samples=list(csv.DictReader((q/f'R-esxi12-{i}-samples.tsv').read_text().splitlines(),delimiter='\t'))
 assert len(samples)==t['joint_samples_taken']
 for row in samples[-3:]:assert [row[c] for c in ['ready_clamav','traffic','eicar','phase','counted']]==['ok','ok','av','ok','yes']
 assert abs(float(samples[-1]['sample_end_s'])-t['recovery_seconds'])<.002
 assert t['recovery_seconds']<=t['budget_seconds']==120
 trials.append({'trial':i,'recovery_seconds':t['recovery_seconds'],'joint_samples':len(samples),'last_three_joint_pass':True})
evidence['record_counts']=counts;evidence['trials']=trials
(root/'image-and-oracle-verification.json').write_text(json.dumps(evidence,indent=2)+'\n')
print(json.dumps(evidence))
