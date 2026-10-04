#!/usr/bin/env python3
"""Write an exclusive local timing marker; never records request contents."""
import datetime
import json
from pathlib import Path
import sys
import time

row={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'monotonic_ns':time.monotonic_ns()}
if len(sys.argv)==3:row['transport_exit']=int(sys.argv[2])
with Path(sys.argv[1]).open('x',encoding='utf-8') as output:json.dump(row,output)
