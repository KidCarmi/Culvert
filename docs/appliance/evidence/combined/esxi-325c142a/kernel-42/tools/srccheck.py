import sys,gzip,re,collections
def filesecs(path):
    secs=collections.defaultdict(list); cur=None
    for l in gzip.open(path,"rt",errors="replace"):
        if l.startswith("+++ "):
            cur=re.sub(r"^\+\+\+ [^/]+/","",l.split("\t")[0].strip()); continue
        if cur and l.startswith("+") : secs[cur].append(l[1:].rstrip("\n").strip())
    return {k:set(v) for k,v in secs.items()}
d38=filesecs(sys.argv[1]); d42=filesecs(sys.argv[2])
for pf in sys.argv[3:]:
    added=collections.defaultdict(list); cur=None
    for l in open(pf,errors="replace"):
        if l.startswith("+++ "): cur=l[4:].strip()[2:]; continue
        if cur and l.startswith("+") and not l.startswith("+++"):
            s=l[1:].strip()
            if len(s)>=12 and not s.startswith(("/*","*","//")): added[cur].append(s)
    tot=sum(len(v) for v in added.values())
    h38=sum(1 for f,v in added.items() for s in v if s in d38.get(f,()))
    h42=sum(1 for f,v in added.items() for s in v if s in d42.get(f,()))
    print("%s files=%s added=%d in38=%d in42=%d"%(pf.split(".")[0],",".join(sorted(added)),tot,h38,h42))
