#!/usr/bin/env python3
"""Compare experimental C against the independent float reference on RAW crops."""
import ctypes, hashlib, json, subprocess, sys, tempfile
from pathlib import Path
import numpy as np
from s33_mono_raw_offline import luminance

root = Path(__file__).resolve().parent.parent
src = root/'AkeruOS/camera/mono_raw.c'
inputs = [root/'RawsAnalysis'/f'DSCo{n}.raw' for n in (1003,1012)]
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
before = {str(p):sha(p) for p in [src,*inputs,Path(__file__)]}
with tempfile.TemporaryDirectory() as temp:
    so = Path(temp)/'mono.so'
    subprocess.run(['cc','-std=c11','-O2','-shared','-fPIC',str(src),'-o',str(so)],check=True)
    f = ctypes.CDLL(str(so)).akeru_mono_raw
    ptr = ctypes.POINTER(ctypes.c_uint16)
    f.argtypes = [ptr,ptr,ctypes.c_size_t,ctypes.c_size_t]
    f.restype = ctypes.c_int
    rows=[]
    for p in inputs:
        a=np.memmap(p,dtype='<u2',mode='r',shape=(3152,4208))
        for y,x in [(0,0),(1250,2000),(3136,4192)]:
            crop=np.ascontiguousarray(a[y:y+16,x:x+16]); out=np.empty_like(crop)
            assert f(crop.ctypes.data_as(ptr),out.ctypes.data_as(ptr),16,16)==0
            ref=luminance(crop,('RG','GB'),[0]*3,[4092]*3,[[1.75,0,0],[0,1,0],[0,0,1.43]])*4092
            err=float(np.max(np.abs(out.astype(float)-ref)))
            assert err < 0.7, (str(p),y,x,err)
            rows.append(dict(raw=p.name,y=y,x=x,pixels=256,max_error_raw_units=err))
assert all(sha(Path(p))==h for p,h in before.items())
print(json.dumps(dict(status='PASS_HOST_REAL_CROPS', inputs=before, cases=rows),indent=2))
