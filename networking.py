"""Network probe primitives."""
import platform, re, time, socket
from process_utils import run_hidden

def ping_once(host, timeout_ms=1500):
    if platform.system().lower() == "windows": cmd=["ping","-n","1","-w",str(timeout_ms),host]
    else: cmd=["ping","-n","-c","1","-W",str(max(1,(timeout_ms+999)//1000)),host]
    try:
        p=run_hidden(cmd,capture_output=True,text=True,timeout=timeout_ms/1000+2)
        output=(p.stdout+p.stderr).replace(",",".")
        m=re.search(r"time[=<]\s*([\d.]+)\s*ms",output,re.I)
        if m: return float(m.group(1))
        if re.search(r"time<\s*1\s*ms",output,re.I): return 0.5
    except (TimeoutError,FileNotFoundError,OSError): pass
    return None

def tcp_connect_once(host,port,timeout=2.0):
    start=time.perf_counter()
    try:
        with socket.create_connection((host,int(port)),timeout=timeout): return (time.perf_counter()-start)*1000
    except (OSError,ValueError,TimeoutError): return None
