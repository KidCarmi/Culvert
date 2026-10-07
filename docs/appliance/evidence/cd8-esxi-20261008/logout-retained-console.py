"""Return the completed lab's authenticated console to its public menu once."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import time

ROOT=Path('D:/AI/Culvert-esxi-cd8-final-controller')
HERE=ROOT/'test/e2e/appliance/esxi'
OPS=ROOT/'.tools/private-operations'
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
load('logout_freeze',HERE/'controller-freeze.py').verify(ROOT/'.tools/controller-freeze.json',ROOT)
w=load('logout_wrapper',ROOT/'.tools/run-final.py');os.environ.update(w.ENV)
c=load('logout_console',HERE/'console-priv.py')
lab=c.b.module.Lab(ROOT/'.tools/scope-cd8-fresh-final.json')
record=OPS/'retained-console-logout.json'
assert not record.exists()
with c.b.module.locked(lab.run):
    con=c.Console(lab)
    text=con.screen(time.monotonic()+25)
    assert con.shell_prompt(text)
    record.write_text(json.dumps({'stage':'verified-shell-exit-intent','helper_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}),encoding='utf-8')
    con.enter('exit')
    deadline=time.monotonic()+30
    while True:
        text=con.screen(deadline)
        assert c.b.classify(text) not in {'password','current','new','repeat','rejected'}
        if 'Press Enter to return' in text:break
        assert time.monotonic()<deadline
        time.sleep(1)
    con.keyboard.send('KEY_ENTER')
    con.wait({'admin'},timeout=30)
    con.keyboard.send('KEY_Q')
    deadline=time.monotonic()+30
    while True:
        text=con.screen(deadline)
        assert c.b.classify(text) not in {'password','current','new','repeat','rejected'}
        if 'Read-only public console' in text and 'L/F2 Sign in' in text:break
        assert time.monotonic()<deadline
        time.sleep(1)
    assert c.b.extract_initial(text) is None and 'bash-5.2$' not in text
    assert 'https://192.168.1.111:9090' in text and 'https://192.168.1.189' not in text
    captures=sorted(lab.sec.glob('capture-*'),key=lambda p:p.stat().st_mtime_ns)
    images=list(captures[-1].glob('*.png'));assert len(images)==1
    target=OPS/'retained-console-public.png'
    with target.open('xb') as output:output.write(images[0].read_bytes())
    record.write_text(json.dumps({'result':'pass','stage':'public-menu','uuid':lab.state['uuid'],
                                 'helper_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                                 'screenshot_sha256':hashlib.sha256(target.read_bytes()).hexdigest(),
                                 'text_sha256':hashlib.sha256(text.encode()).hexdigest()}),encoding='utf-8')
print('PASS retained console returned to read-only public menu')
