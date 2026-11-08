#!/usr/bin/env python3
"""Offline acquisition tests through Python SG_IO ABI and the actual C AKRN core."""
from datetime import datetime,timezone
from pathlib import Path
from unittest.mock import patch
import contextlib,ctypes as C,hashlib,io,json,subprocess,sys
from s33_run_gnu_arc700 import ROOT,sha
import s33_nand_pc_read as client
import s33_nand_pc_dump as dump


def main():
    out=ROOT/'Risultati/USB_SCSI/Accesso_NAND_PC'/datetime.now(timezone.utc).strftime('pc_dump_%Y%m%dT%H%M%SZ');out.mkdir(parents=True,exist_ok=False)
    try:
        core=ROOT/'S33-sections/usb_nand_readonly/akrn_read.c'
        command=['cc','-shared','-fPIC','-Wall','-Wextra','-Werror',str(core),'-o',str(out/'libakrn.so')]
        p=subprocess.run(command,capture_output=True,text=True,check=True);(out/'compile.log').write_text(p.stdout+p.stderr);(out/'compile.command.json').write_text(json.dumps(command,indent=2)+'\n')
        class Geometry(C.Structure):_fields_=[(n,C.c_uint32)for n in ['chips','blocks_per_chip','pages_per_block','data_bytes','oob_bytes']]
        class Result(C.Structure):_fields_=[('status',C.c_int),('io_status',C.c_int),('length',C.c_uint32)]
        callback=C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_uint8,C.c_uint16,C.c_uint8,C.c_void_p,C.c_size_t)
        lib=C.CDLL(str(out/'libakrn.so'));core_read=lib.akrn_read_page;core_read.restype=Result
        core_read.argtypes=[C.c_void_p,C.c_size_t,C.c_uint8,C.c_uint32,C.POINTER(Geometry),C.c_void_p,C.c_size_t,callback,C.c_void_p]
        geometry=Geometry(256,512,64,2048,64)
        def pattern(chip,block,page):
            return bytes((chip,block>>8,block&255,page))*528
        cases=[]
        for name,mode,expected_pages in [('two_blocks','ok',128),('last_block','last',64),('mismatch_second_read','mismatch',3),('short_second_read','short',3),('scsi_error','scsi',3),('ioctl_error','ioctl',3),('interrupted','interrupt',3),('progress_manifest_failure','disk',64),('final_manifest_failure','final_disk',128)]:
            directory=out/name;directory.mkdir();calls=[];core_coordinates=[]
            first_block,blocks=(511,1)if mode=='last'else(255,2)
            @callback
            def reader(ctx,chip,block,page,buffer,size):
                core_coordinates.append([chip,block,page]);data=pattern(chip,block,page);assert size==len(data)==2112
                C.memmove(buffer,data,size);return 0
            def ioctl(fd,request,header,mutate):
                h=client.SgIo.from_buffer(header);assert fd==123 and request==client.SG_IO and mutate is True
                assert h.dxfer_direction==client.SG_DXFER_FROM_DEV and h.cmd_len==16 and h.dxfer_len==2112
                cdb=C.string_at(h.cmdp,h.cmd_len);calls.append(cdb.hex())
                result=core_read(cdb,h.cmd_len,0x80,h.dxfer_len,C.byref(geometry),h.dxferp,h.dxfer_len,reader,None)
                assert result.status==0 and result.length==2112
                if len(calls)==8:
                    if mode=='mismatch':C.memset(h.dxferp,0xff,1)
                    elif mode=='short':h.resid=1
                    elif mode=='scsi':h.status=2
                    elif mode=='ioctl':raise OSError('simulated SG_IO failure')
                    elif mode=='interrupt':raise KeyboardInterrupt('simulated interruption')
                return 0
            saved_json=dump.write_json;writes=[]
            def controlled_json(path,value):
                writes.append(value['status'])
                if (mode=='disk' and len(writes)==2) or (mode=='final_disk' and len(writes)==4):raise OSError('simulated progress manifest write failure')
                return saved_json(path,value)
            error=None
            with patch.object(client.fcntl,'ioctl',side_effect=ioctl),patch.object(dump,'write_json',side_effect=controlled_json):
                try:result=dump.acquire(123,1,first_block,blocks,directory,dict(test_only=True),reader=client.read_page)
                except (OSError,KeyboardInterrupt)as exc:error=exc
            manifest=json.loads((directory/'manifest.json').read_text());journal=[json.loads(line)for line in (directory/'pages.jsonl').read_text().splitlines()]
            good=mode in ('ok','last');assert (error is None)==good
            assert manifest['pages_written']==len(journal)==expected_pages
            expected=[pattern(1,b,p)for b in range(first_block,first_block+blocks)for p in range(64)][:expected_pages]
            path=directory/('dump.raw'if good else'dump.raw.partial');data=path.read_bytes();assert data==b''.join(expected)
            wanted_coordinates=[[1,b,p]for b in range(first_block,first_block+blocks)for p in range(64)]
            if good:
                assert manifest['status']=='COMPLETE_DOUBLE_READ_LOCAL_FILE_VERIFIED'and manifest['sha256']==hashlib.sha256(data).hexdigest()
                assert len(calls)==expected_pages*2 and core_coordinates==[v for c in wanted_coordinates for v in [c,c]]
                assert not (directory/'dump.raw.partial').exists()
            else:
                assert manifest['status']=='FAILED'and not (directory/'dump.raw').exists()
                expected_failed=dict(chip=1,block=256 if mode=='final_disk' else 255,page=63 if mode in ('disk','final_disk') else 3)
                assert manifest['failed_coordinate']==expected_failed,(mode,manifest)
            for i,row in enumerate(journal):
                assert [row['chip'],row['block'],row['page']]==wanted_coordinates[i]
                assert row['offset']==i*2112 and row['bytes']==2112 and row['sha256']==hashlib.sha256(expected[i]).hexdigest()
            cases.append(dict(name=name,status=manifest['status'],pages_written=expected_pages,transport_calls=len(calls),sha256=hashlib.sha256(data).hexdigest(),expected_error=type(error).__name__ if error else None))
        invalid=[(0,0,0),(0,511,2),(0,-1,1),(0,512,1),(-1,0,1),(256,0,1)]
        for args in invalid:
            try:dump.validate_range(*args)
            except ValueError:pass
            else:raise AssertionError(args)
        # Existing directory cannot trigger an open or a request, through the real CLI.
        argv=['s33_nand_pc_dump.py','--device','/dev/unused','--first-block','0','--blocks','1','--output-dir',str(out/'two_blocks')]
        with patch.object(sys,'argv',argv),patch.object(dump.os,'open')as opened:
            try:dump.main()
            except FileExistsError:pass
            else:raise AssertionError('existing directory accepted')
            opened.assert_not_called()
        regular=out/'regular_file';regular.write_bytes(b'not a device');argv[2]=str(regular);argv[-1]=str(out/'identity_failure')
        with patch.object(sys,'argv',argv),patch.object(client.fcntl,'ioctl')as transport:
            try:dump.main()
            except ValueError:pass
            else:raise AssertionError('regular file identity accepted')
            transport.assert_not_called()
        identity=json.loads((out/'identity_failure/manifest.json').read_text());assert identity['status']=='FAILED_BEFORE_ACQUISITION'and identity['pages_written']==0
        # A complete CLI run uses read-only open flags and closes the exact descriptor.
        argv[2]='/dev/fixture';argv[-1]=str(out/'cli_success')
        with patch.object(sys,'argv',argv),patch.object(dump.os,'open',return_value=123)as opened,patch.object(dump.os,'close')as closed,patch.object(dump,'fd_identity',return_value=dict(test_only=True)),patch.object(dump,'read_page')as unused,contextlib.redirect_stdout(io.StringIO()):
            # acquire's default is intentionally bound to the real read_page, so route through SG_IO.
            with patch.object(client.fcntl,'ioctl',side_effect=ioctl):dump.main()
            opened.assert_called_once_with('/dev/fixture',dump.os.O_RDONLY|dump.os.O_NONBLOCK|dump.os.O_CLOEXEC);closed.assert_called_once_with(123);unused.assert_not_called()
        (out/'cases.json').write_text(json.dumps(cases,indent=2)+'\n')
        files=[Path(__file__),Path(client.__file__),Path(dump.__file__),core,core.with_suffix('.h')]
        for file in files:(out/file.name).write_bytes(file.read_bytes())
        result=dict(status='PASS_PC_BLOCK_DUMP_OFFLINE_ONLY',cases=cases,coordinate_refusals=len(invalid),cli_checks=['existing directory no device open','regular file rejected before SG_IO','O_RDONLY exact descriptor opened and closed'],source_hashes={str(p):sha(p)for p in files},limits=['SG_IO is a Python fixture feeding the actual native C AKRN core','No real device or kernel USB path; all page bytes are synthetic','No installed candidate, full physical chip, ECC or recovery test'])
        (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n');(out.parent/'pc_dump_latest.json').write_text(json.dumps(dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))),indent=2)+'\n');print('PASS',out)
    except BaseException as exc:
        (out/'failure.json').write_text(json.dumps(dict(status='FAIL',error=repr(exc)),indent=2)+'\n');raise
if __name__=='__main__':main()
