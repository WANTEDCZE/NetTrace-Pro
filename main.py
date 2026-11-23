import sys, os, re, time, csv, sqlite3, platform, subprocess, shutil, statistics
from collections import deque, defaultdict
from datetime import datetime, timedelta
from PySide6.QtCore import Qt, QThread, Signal, QTimer, QSettings, QMarginsF, QSizeF
from PySide6.QtGui import QPainter, QPen, QColor, QFont, QPdfWriter, QTextDocument, QPageSize, QPageLayout
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem, QHeaderView,
    QSplitter, QGroupBox, QMessageBox, QFileDialog, QSpinBox, QComboBox,
    QTabWidget, QStatusBar, QFrame, QDialog, QFormLayout, QProgressBar, QSizePolicy,
    QAbstractItemView
)

APP_NAME = "NetTrace Pro"
DB_PATH = os.path.join(os.path.expanduser("~"), ".nettrace_pro", "history.sqlite3")
MAX_GRAPH_POINTS = 240
MAX_ROUTE_COLUMNS = 12

def db_connect():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    return sqlite3.connect(DB_PATH)

def ensure_db():
    with db_connect() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS samples (
            id INTEGER PRIMARY KEY, target TEXT, timestamp TEXT,
            latency REAL, packet_loss INTEGER)""")
        db.execute("""CREATE TABLE IF NOT EXISTS hop_samples (
            id INTEGER PRIMARY KEY, target TEXT, timestamp TEXT,
            hop INTEGER, address TEXT, latency REAL)""")
        db.execute("CREATE INDEX IF NOT EXISTS idx_samples_target_time ON samples(target,timestamp)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_hops_target_time ON hop_samples(target,timestamp)")
        db.execute("""CREATE TABLE IF NOT EXISTS tcp_samples (
            id INTEGER PRIMARY KEY, target TEXT, port INTEGER, timestamp TEXT,
            connect_ms REAL, success INTEGER)""")
        db.execute("""CREATE TABLE IF NOT EXISTS comparison_samples (
            id INTEGER PRIMARY KEY, target TEXT, port INTEGER, timestamp TEXT,
            icmp_ms REAL, tcp_ms REAL)""")
        db.execute("CREATE INDEX IF NOT EXISTS idx_tcp_target_time ON tcp_samples(target,port,timestamp)")

def ping_once(host, timeout_ms=1500):
    if platform.system().lower() == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), host]
    else:
        cmd = ["ping", "-n", "-c", "1", "-W", str(max(1, (timeout_ms + 999)//1000)), host]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_ms/1000 + 2)
        output = (p.stdout + p.stderr).replace(",", ".")
        m = re.search(r"time[=<]\s*([\d.]+)\s*ms", output, re.I)
        if m:
            return float(m.group(1))
        if re.search(r"time<\s*1\s*ms", output, re.I):
            return 0.5
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def write_excel_csv(path, headers, rows):
    """Write a UTF-8 CSV that opens in Czech-localized Excel."""
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f, delimiter=";", lineterminator="\r\n")
        writer.writerow(headers)
        for row in rows:
            # Czech Excel expects a comma decimal separator when fields are
            # separated by semicolons. Keep timestamps and integer fields intact.
            writer.writerow([
                (str(value).replace(".", ",") if isinstance(value, float) else value)
                for value in row
            ])


def get_hop_report_summary(target, limit=10000):
    """Return per-hop statistics from the latest stored traceroute samples."""
    with db_connect() as db:
        rows = db.execute(
            "SELECT hop,address,latency,timestamp FROM hop_samples "
            "WHERE target=? ORDER BY timestamp DESC,id DESC LIMIT ?",
            (target, int(limit)),
        ).fetchall()
    grouped = defaultdict(list)
    for hop, address, latency, stamp in reversed(rows):
        grouped[int(hop)].append((address or "—", latency, stamp))

    result = []
    for hop in sorted(grouped):
        samples = grouped[hop]
        valid = [float(item[1]) for item in samples if item[1] is not None]
        diffs = [
            abs(float(samples[i][1]) - float(samples[i - 1][1]))
            for i in range(1, len(samples))
            if samples[i][1] is not None and samples[i - 1][1] is not None
        ]
        addresses = [item[0] for item in samples if item[0] not in ("", "—", "*")]
        latest_address = addresses[-1] if addresses else (samples[-1][0] if samples else "—")
        address_changes = sum(addresses[i] != addresses[i - 1] for i in range(1, len(addresses)))
        losses = sum(item[1] is None for item in samples)
        result.append({
            "hop": hop,
            "address": latest_address,
            "current": samples[-1][1],
            "average": statistics.mean(valid) if valid else None,
            "minimum": min(valid) if valid else None,
            "maximum": max(valid) if valid else None,
            "jitter": statistics.mean(diffs) if diffs else None,
            "loss_pct": 100.0 * losses / len(samples) if samples else 0.0,
            "losses": losses,
            "samples": len(samples),
            "address_changes": address_changes,
            "last_seen": samples[-1][2],
        })
    return result



def load_route_snapshots(target, limit=MAX_ROUTE_COLUMNS):
    """Restore the most recent complete traceroute scans for a target from SQLite."""
    with db_connect() as db:
        stamps = [row[0] for row in db.execute(
            "SELECT DISTINCT timestamp FROM hop_samples WHERE target=? "
            "ORDER BY timestamp DESC LIMIT ?", (target, int(limit))
        ).fetchall()]
        if not stamps:
            return []
        placeholders = ",".join("?" for _ in stamps)
        rows = db.execute(
            f"SELECT timestamp,hop,address,latency FROM hop_samples "
            f"WHERE target=? AND timestamp IN ({placeholders}) ORDER BY timestamp,hop,id",
            (target, *stamps)
        ).fetchall()
    by_stamp = {}
    for stamp, hop, address, latency in rows:
        by_stamp.setdefault(stamp, {})[int(hop)] = (address or "—", latency)
    return [by_stamp[stamp] for stamp in sorted(by_stamp)][-int(limit):]


def route_diagnosis_flags(snapshots):
    """Return conservative per-hop flags for visual highlighting in the route heatmap."""
    if not snapshots:
        return {}
    recent = snapshots[-5:]
    latest = recent[-1]
    flags = {}
    placeholder = ("", "—", "*", None)

    if len(recent) >= 2:
        previous = recent[-2]
        for hop, observation in latest.items():
            old = previous.get(hop)
            new_addr = observation[0] if observation else None
            old_addr = old[0] if old else None
            if old_addr not in placeholder and new_addr not in placeholder and old_addr != new_addr:
                flags[hop] = ("ROUTE CHANGE", "route")

    hops = sorted(latest)
    for hop in hops[:-1]:
        observations = [snap.get(hop) for snap in recent]
        losses = sum(obs is None or obs[1] is None for obs in observations)
        downstream = sum(
            any((obs := snap.get(later)) is not None and obs[1] is not None
                for later in hops if later > hop) for snap in recent
        )
        if losses >= max(2, (len(recent) + 1) // 2) and downstream >= max(1, (len(recent) * 2 + 2) // 3):
            flags.setdefault(hop, ("ICMP FILTER / RATE LIMIT", "caution"))

    medians = {}
    for hop in hops:
        vals = [float(obs[1]) for snap in recent
                if (obs := snap.get(hop)) is not None and obs[1] is not None]
        if len(vals) >= min(3, len(recent)):
            medians[hop] = statistics.median(vals)
    for left, right in zip(hops, hops[1:]):
        if left in medians and right in medians:
            delta = medians[right] - medians[left]
            if delta >= max(35.0, medians[left] * 0.75):
                flags.setdefault(right, (f"RTT +{delta:.0f} ms", "latency"))

    for hop in hops:
        vals = [float(obs[1]) for snap in recent
                if (obs := snap.get(hop)) is not None and obs[1] is not None]
        if len(vals) >= 4:
            jitter = statistics.mean(abs(vals[i] - vals[i-1]) for i in range(1, len(vals)))
            if jitter >= 25:
                flags.setdefault(hop, (f"HIGH JITTER {jitter:.0f} ms", "caution"))

    if hops:
        final_hop = hops[-1]
        final = [snap.get(final_hop) for snap in recent]
        losses = sum(obs is None or obs[1] is None for obs in final)
        if len(recent) >= 3 and losses >= max(2, (len(recent)+1)//2):
            flags.setdefault(final_hop, ("FINAL HOP NOT REPLYING", "latency"))
    return flags


def analyze_route_snapshots(snapshots):
    """Conservative, evidence-based interpretation of recent traceroute snapshots."""
    if not snapshots:
        return "Route diagnosis: waiting for traceroute samples."

    recent = snapshots[-5:]
    latest = recent[-1]
    if not latest:
        return "Route diagnosis: the latest scan returned no hop data."

    notes = []
    placeholders = ("", "—", "*", None)

    # Detect address changes between the two most recent successful scans.
    if len(recent) >= 2:
        previous = recent[-2]
        changes = []
        for hop, observation in latest.items():
            old = previous.get(hop)
            new_address = observation[0] if observation else None
            old_address = old[0] if old else None
            if (old_address not in placeholders and new_address not in placeholders
                    and old_address != new_address):
                changes.append(f"hop {hop}: {old_address} → {new_address}")
        if changes:
            notes.append("Route changed (" + "; ".join(changes[:3]) + ").")

    hops = sorted(latest)
    # A hop that times out while later hops keep replying is usually filtering
    # or ICMP rate limiting, not proof of forwarding loss.
    for hop in hops[:-1]:
        observations = [snap.get(hop) for snap in recent]
        count = len(observations)
        losses = sum(obs is None or obs[1] is None for obs in observations)
        downstream_replies = sum(
            1 for snap in recent
            if any((obs := snap.get(later)) is not None and obs[1] is not None
                   for later in hops if later > hop)
        )
        threshold = max(2, (count + 1) // 2)
        if losses >= threshold and downstream_replies >= max(1, (count * 2 + 2) // 3):
            notes.append(
                f"Hop {hop} misses replies while later hops respond; likely ICMP "
                "rate limiting/deprioritization rather than confirmed packet loss."
            )
            break

    # If the final observed hop repeatedly fails to answer, report it as a
    # possible endpoint/route issue, not a definitive outage (the route may
    # simply be capped by the max-hop setting).
    final_hop = hops[-1]
    final_obs = [snap.get(final_hop) for snap in recent]
    final_losses = sum(obs is None or obs[1] is None for obs in final_obs)
    if len(recent) >= 3 and final_losses >= max(2, (len(recent) + 1) // 2):
        notes.append(
            f"Last observed hop {final_hop} is not replying consistently; "
            "destination filtering, an outage, or the traceroute hop limit may be involved."
        )

    # Detect a large, repeated RTT step between adjacent hops. This is a
    # diagnostic hint only: hop RTTs are round-trip measurements and are not
    # additive link-delay measurements.
    medians = {}
    for hop in hops:
        vals = [
            float(obs[1]) for snap in recent
            if (obs := snap.get(hop)) is not None and obs[1] is not None
        ]
        if len(vals) >= min(3, len(recent)):
            medians[hop] = statistics.median(vals)
    for left, right in zip(hops, hops[1:]):
        if left in medians and right in medians:
            delta = medians[right] - medians[left]
            if delta >= max(35.0, medians[left] * 0.75):
                notes.append(
                    f"Large RTT increase between hops {left} and {right} "
                    f"(about +{delta:.1f} ms median); investigate this segment."
                )
                break

    # High variation at a hop can indicate an unstable path, but only report
    # it when enough valid samples exist.
    for hop in hops:
        vals = [
            float(obs[1]) for snap in recent
            if (obs := snap.get(hop)) is not None and obs[1] is not None
        ]
        if len(vals) >= 4:
            jitter = statistics.mean(abs(vals[i] - vals[i - 1]) for i in range(1, len(vals)))
            if jitter >= 25:
                notes.append(f"Hop {hop} has elevated RTT variation (about {jitter:.1f} ms).")
                break

    if not notes:
        return "Route diagnosis: no persistent route anomaly detected in the recent scans."
    return "Route diagnosis: " + " ".join(notes) + (
        " Interpret intermediate-hop loss cautiously; routers may limit diagnostic replies."
    )


class PingWorker(QThread):
    sample = Signal(str, object, str)
    def __init__(self, target, interval_ms=1000, timeout_ms=1500):
        super().__init__()
        self.target, self.interval_ms, self.timeout_ms = target, interval_ms, timeout_ms
        self.running = True
    def stop(self):
        self.running = False
    def run(self):
        while self.running:
            start = time.monotonic()
            value = ping_once(self.target, self.timeout_ms)
            self.sample.emit(self.target, value, datetime.now().isoformat(timespec="seconds"))
            wait = max(0, self.interval_ms - int((time.monotonic()-start)*1000))
            deadline = time.monotonic() + wait/1000
            while self.running and time.monotonic() < deadline:
                self.msleep(40)

class TraceWorker(QThread):
    result = Signal(str, list, str)
    def __init__(self, target, max_hops=20):
        super().__init__()
        self.target, self.max_hops = target, max_hops
    def run(self):
        system = platform.system().lower()
        if system == "windows":
            cmd = ["tracert", "-d", "-h", str(self.max_hops), "-w", "250", self.target]
        else:
            exe = shutil.which("traceroute") or shutil.which("tracepath")
            if not exe:
                self.result.emit(self.target, [], "Traceroute is not installed. Ubuntu/Debian: sudo apt install traceroute")
                return
            if os.path.basename(exe) == "tracepath":
                cmd = [exe, "-n", "-m", str(self.max_hops), self.target]
            else:
                cmd = [exe, "-n", "-q", "1", "-m", str(self.max_hops), "-w", "0.25", self.target]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            rows = []
            for line in p.stdout.splitlines():
                m = re.match(r"\s*(\d+)\s+(.*)", line)
                if not m:
                    continue
                hop, rest = int(m.group(1)), m.group(2).strip()
                if hop > self.max_hops:
                    continue
                times = re.findall(r"(\d+(?:[.,]\d+)?)\s*ms", rest, re.I)
                ips = re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])|[0-9a-fA-F:]{3,}", rest)
                latency = statistics.mean(float(x.replace(",", ".")) for x in times) if times else None
                address = ips[-1] if ips else ("*" if "*" in rest else "—")
                rows.append((hop, address, latency, rest))
            msg = p.stderr.strip() or ("Traceroute completed." if rows else "No hop data received. Check traceroute availability.")
            self.result.emit(self.target, rows, msg)
        except Exception as e:
            self.result.emit(self.target, [], str(e))

class LatencyGraph(QWidget):
    WINDOWS = {"1 minute": 60, "5 minutes": 300, "15 minutes": 900, "1 hour": 3600, "6 hours": 21600, "12 hours": 43200, "24 hours": 86400}
    def __init__(self, title="Ping"):
        super().__init__(); self.values=deque(maxlen=3600); self.title=title
        self.window_seconds=300; self.view_end=time.time(); self.drag_x=None; self.follow=True
        self.setMinimumHeight(85); self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
    def set_window(self, seconds): self.window_seconds=max(10,min(2592000,seconds)); self.view_end=time.time(); self.follow=True; self.update()
    def wheelEvent(self,event):
        old=self.window_seconds; factor=0.8 if event.angleDelta().y()>0 else 1.25; new=max(10,min(2592000,int(old*factor)))
        pos=max(0,min(1,event.position().x()/max(1,self.width()))); anchor=self.view_end-old*(1-pos); self.window_seconds=new; self.view_end=anchor+new*(1-pos); self.follow=False; self.update()
    def mousePressEvent(self,event):
        if event.button()==Qt.LeftButton: self.drag_x=event.position().x(); self.follow=False
    def mouseMoveEvent(self,event):
        if self.drag_x is not None:
            dx=event.position().x()-self.drag_x; self.drag_x=event.position().x(); self.view_end-=dx/max(1,self.width())*self.window_seconds; self.update()
    def mouseReleaseEvent(self,event): self.drag_x=None
    def add_value(self, value, timestamp=None):
        ts=timestamp or time.time(); self.values.append((ts,value));
        if self.follow: self.view_end=ts
        self.update()
    def paintEvent(self,event):
        p=QPainter(self); p.setRenderHint(QPainter.Antialiasing); p.fillRect(self.rect(),QColor("#0b1220"))
        w,h=self.width(),self.height(); left,right,top,bottom=58,16,26,34; gw,gh=max(1,w-left-right),max(1,h-top-bottom)
        now=self.view_end; data=[(t,v) for t,v in self.values if now-self.window_seconds<=t<=now]
        valid=[v for _,v in data if v is not None]
        peak=max(10, (max(valid,default=10)*1.25)); peak=round(peak/10)*10 if peak>10 else 10
        p.setPen(QPen(QColor("#26354b"),1))
        for i in range(5):
            y=int(top+gh*i/4); p.drawLine(left,y,w-right,y)
            value=peak*(1-i/4); p.setPen(QColor("#9aa9bd")); p.setFont(QFont("Segoe UI",8)); p.drawText(4,y+4,f"{value:.0f} ms"); p.setPen(QPen(QColor("#26354b"),1))
        for i in range(5):
            x=int(left+gw*i/4); p.drawLine(x,top,x,top+gh)
            secs=self.window_seconds*(1-i/4); label=(f"-{int(secs/3600)}h" if secs>=3600 else (f"-{int(secs/60)}m" if secs>=60 else f"-{int(secs)}s")) if i<4 else "End"
            p.setPen(QColor("#9aa9bd")); p.drawText(x-18,h-8,label); p.setPen(QPen(QColor("#26354b"),1))
        p.setPen(QColor("#e2e8f0")); p.setFont(QFont("Segoe UI",9,QFont.Bold)); p.drawText(left,17,self.title)
        if valid:
            avg=statistics.mean(valid); lo=min(valid); hi=max(valid)
            p.setPen(QColor("#94a3b8")); p.drawText(left+100,17,f"min {lo:.1f} · avg {avg:.1f} · max {hi:.1f} ms")
        if len(data)<2: p.setPen(QColor("#94a3b8")); p.drawText(left+10,top+30,"Waiting for samples in this time range…"); return
        pts=[]
        for t,v in data:
            x=left+gw*max(0,min(1,(t-(now-self.window_seconds))/self.window_seconds)); y=top+gh if v is None else top+gh-min(v,peak)/peak*gh
            pts.append((int(x),int(y),v))
        # Soft area beneath valid samples, line segments, and clearly marked outages
        for a,b in zip(pts,pts[1:]):
            if a[2] is not None and b[2] is not None:
                p.setPen(QPen(QColor("#38bdf8"),2)); p.drawLine(a[0],a[1],b[0],b[1])
            elif a[2] is None or b[2] is None:
                p.setPen(QPen(QColor("#fb7185"),1,Qt.DashLine)); p.drawLine(a[0],top+gh-2,b[0],top+gh-2)
        for x,y,v in pts:
            p.setBrush(QColor("#fb7185") if v is None else QColor("#7dd3fc")); p.setPen(QPen(QColor("#0b1220"),1)); p.drawEllipse(x-3,y-3,6,6)

class HopHeatmap(QWidget):
    # The first nine columns are live statistics; the remaining columns are
    # the recent route samples used by the heatmap.
    BASE_COLUMNS = 10

    def __init__(self):
        super().__init__()
        layout=QVBoxLayout(self); layout.setContentsMargins(0,0,0,0)
        self.info=QLabel("Hop history will appear after the first automatic traceroute. Double-click a hop for detailed history.")
        self.info.setStyleSheet("color:#94a3b8")
        layout.addWidget(self.info)
        self.table=QTableWidget(0,self.BASE_COLUMNS+MAX_ROUTE_COLUMNS)
        self.table.setHorizontalHeaderLabels(["Hop","IP / Host","Current","Avg RTT","Min","Max","Jitter","Loss","Samples","Route flag"]+[f"Sample {i+1}" for i in range(MAX_ROUTE_COLUMNS)])
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(1,QHeaderView.Stretch)
        for c in (0,2,3,4,5,6,7,8,9):
            self.table.horizontalHeader().setSectionResizeMode(c,QHeaderView.ResizeToContents)
        for c in range(self.BASE_COLUMNS,self.BASE_COLUMNS+MAX_ROUTE_COLUMNS):
            self.table.horizontalHeader().setSectionResizeMode(c,QHeaderView.ResizeToContents)
        self.table.setAlternatingRowColors(True)
        self.table.setWordWrap(False)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setDefaultSectionSize(25)
        self.table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.table.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.table.setToolTip("Double-click a hop row to open its detailed timeline and statistics.")
        self.table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.table.setMinimumHeight(0)
        layout.addWidget(self.table, 1)

    def update_data(self, snapshots):
        # snapshots: [{hop: (address, latency)}], oldest -> newest
        recent=snapshots[-MAX_ROUTE_COLUMNS:]
        # Build diagnostic flags for the same snapshot window displayed in the heatmap.
        # Without this local value, the row renderer references an undefined name.
        flags=route_diagnosis_flags(recent)
        all_hops=sorted({hop for snap in recent for hop in snap})
        self.table.setRowCount(len(all_hops))
        for r,hop in enumerate(all_hops):
            observations=[snap.get(hop) for snap in recent]
            addresses=[x[0] for x in observations if x]
            address=next((a for a in reversed(addresses) if a not in ("—","*")), addresses[-1] if addresses else "—")
            vals=[x[1] if x else None for x in observations]
            valid=[v for v in vals if v is not None]
            avg=statistics.mean(valid) if valid else None
            minimum=min(valid) if valid else None
            maximum=max(valid) if valid else None
            adjacent_diffs=[abs(vals[i]-vals[i-1]) for i in range(1,len(vals)) if vals[i] is not None and vals[i-1] is not None]
            jitter=statistics.mean(adjacent_diffs) if adjacent_diffs else None
            loss=sum(v is None for v in vals)
            current=vals[-1] if vals else None
            base=[str(hop),address,(f"{current:.1f} ms" if current is not None else ("Timeout" if vals else "—")),
                  (f"{avg:.2f} ms" if avg is not None else "—"),
                  (f"{minimum:.2f} ms" if minimum is not None else "—"),
                  (f"{maximum:.2f} ms" if maximum is not None else "—"),
                  (f"{jitter:.2f} ms" if jitter is not None else "—"),
                  (f"{100*loss/max(1,len(observations)):.1f}%" if observations else "—"),str(len(observations)),
                  flags.get(hop, ("", ""))[0]]
            for c,text in enumerate(base):
                item=QTableWidgetItem(text)
                item.setFlags(item.flags() ^ Qt.ItemIsEditable)
                if c==0: item.setData(Qt.UserRole,hop)
                if c==9 and hop in flags:
                    flag_text, flag_kind = flags[hop]
                    palette = {
                        "route": ("#1e3a5f", "#bfdbfe"),
                        "caution": ("#713f12", "#fef3c7"),
                        "latency": ("#7f1d1d", "#fee2e2"),
                    }
                    bg, fg = palette.get(flag_kind, ("#26364c", "#e5edf7"))
                    item.setBackground(QColor(bg)); item.setForeground(QColor(fg))
                    item.setToolTip("Diagnostic hint only; verify with downstream hops and endpoint.")
                elif c in (0,1) and hop in flags:
                    bg = "#332b1a" if flags[hop][1] == "caution" else "#30202a"
                    item.setBackground(QColor(bg))
                self.table.setItem(r,c,item)
            for j in range(MAX_ROUTE_COLUMNS):
                c=self.BASE_COLUMNS+j
                if j < len(recent):
                    obs=recent[j].get(hop); value=obs[1] if obs else None
                    text="×" if value is None else f"{value:.1f}"
                    item=QTableWidgetItem(text); item.setTextAlignment(Qt.AlignCenter)
                    if value is None: item.setBackground(QColor("#7f1d1d")); item.setForeground(QColor("#fecaca"))
                    elif value < 30: item.setBackground(QColor("#14532d")); item.setForeground(QColor("#dcfce7"))
                    elif value < 100: item.setBackground(QColor("#854d0e")); item.setForeground(QColor("#fef3c7"))
                    else: item.setBackground(QColor("#7f1d1d")); item.setForeground(QColor("#fee2e2"))
                else:
                    item=QTableWidgetItem("·"); item.setTextAlignment(Qt.AlignCenter)
                item.setFlags(item.flags() ^ Qt.ItemIsEditable)
                self.table.setItem(r,c,item)
        self.table.setUpdatesEnabled(True)
        self.info.setText(f"{len(recent)} recent route samples · flagged rows show likely route anomalies · double-click a hop for details · green <30 ms · yellow 30–100 ms · red ≥100 ms / timeout")


class HopDetailDialog(QDialog):
    """Historical timeline and statistics for one traceroute hop."""
    PERIODS = {"Last 24 hours": 86400, "Last 7 days": 604800, "Last 30 days": 2592000, "All time": None}

    def __init__(self, parent, target, hop, address):
        super().__init__(parent)
        self.target=target; self.hop=int(hop); self.address=address
        self.setWindowTitle(f"Hop {self.hop} · {self.address} · {self.target}")
        self.resize(1050,720)
        layout=QVBoxLayout(self); layout.setSpacing(9)
        heading=QLabel(f"Hop {self.hop}  ·  {self.address}  ·  Target: {self.target}")
        heading.setStyleSheet("font-size:16px;font-weight:700;color:#e2e8f0")
        layout.addWidget(heading)
        controls=QHBoxLayout(); controls.addWidget(QLabel("Time range:"))
        self.period=QComboBox(); self.period.addItems(list(self.PERIODS))
        controls.addWidget(self.period); controls.addStretch(1)
        self.export_btn=QPushButton("Export hop CSV"); self.export_btn.setObjectName("Tool")
        controls.addWidget(self.export_btn); layout.addLayout(controls)
        self.graph=LatencyGraph(f"Hop {self.hop} latency")
        self.graph.setMinimumHeight(220); layout.addWidget(self.graph,2)
        self.stats_label=QLabel("Loading hop statistics…")
        self.stats_label.setStyleSheet("font-size:13px;color:#cbd5e1;padding:5px")
        self.stats_label.setWordWrap(True); layout.addWidget(self.stats_label)
        self.table=QTableWidget(0,4)
        self.table.setHorizontalHeaderLabels(["Timestamp","IP / Host","Latency","Result"])
        self.table.horizontalHeader().setSectionResizeMode(0,QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1,QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2,QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3,QHeaderView.ResizeToContents)
        self.table.verticalHeader().hide(); self.table.setAlternatingRowColors(True)
        layout.addWidget(self.table,1)
        note=QLabel("Note: intermediate routers may rate-limit or deprioritize traceroute replies. Loss at one hop alone does not prove end-to-end packet loss.")
        note.setStyleSheet("color:#94a3b8;font-size:9px"); note.setWordWrap(True); layout.addWidget(note)
        self.period.currentIndexChanged.connect(self.load_data)
        self.export_btn.clicked.connect(self.export_csv)
        self.load_data()

    def _rows(self):
        seconds=self.PERIODS[self.period.currentText()]
        with db_connect() as db:
            if seconds is None:
                return db.execute("SELECT timestamp,address,latency FROM hop_samples WHERE target=? AND hop=? ORDER BY timestamp,id",(self.target,self.hop)).fetchall()
            cutoff=(datetime.now()-timedelta(seconds=seconds)).isoformat(timespec="seconds")
            return db.execute("SELECT timestamp,address,latency FROM hop_samples WHERE target=? AND hop=? AND timestamp>=? ORDER BY timestamp,id",(self.target,self.hop,cutoff)).fetchall()

    def load_data(self):
        rows=self._rows()
        graph_values=[]
        for stamp,address,latency in rows:
            try: ts=datetime.fromisoformat(stamp).timestamp()
            except (TypeError,ValueError): continue
            graph_values.append((ts,latency))
        self.graph.values=deque(graph_values,maxlen=100000)
        now=time.time(); seconds=self.PERIODS[self.period.currentText()]
        if seconds is None and graph_values:
            seconds=max(60,now-graph_values[0][0]+60)
        self.graph.window_seconds=seconds or 86400
        self.graph.view_end=now; self.graph.follow=True; self.graph.update()
        latencies=[r[2] for r in rows if r[2] is not None]
        losses=sum(r[2] is None for r in rows)
        diffs=[abs(rows[i][2]-rows[i-1][2]) for i in range(1,len(rows)) if rows[i][2] is not None and rows[i-1][2] is not None]
        current=rows[-1][2] if rows else None
        current_text=(f"{current:.2f} ms" if current is not None else ("Timeout" if rows else "—"))
        avg=f"{statistics.mean(latencies):.2f} ms" if latencies else "—"
        minimum=f"{min(latencies):.2f} ms" if latencies else "—"
        maximum=f"{max(latencies):.2f} ms" if latencies else "—"
        jitter=f"{statistics.mean(diffs):.2f} ms" if diffs else "—"
        loss_pct=100*losses/len(rows) if rows else 0
        self.stats_label.setText(f"Current: {current_text}    Average: {avg}    Min: {minimum}    Max: {maximum}    Jitter: {jitter}    Packet loss: {loss_pct:.1f}% ({losses}/{len(rows)})    Samples: {len(rows)}")
        shown=rows[-500:]
        self.table.setRowCount(len(shown))
        for i,(stamp,address,latency) in enumerate(reversed(shown)):
            values=[stamp,address,(f"{latency:.2f} ms" if latency is not None else "—"),("Timeout" if latency is None else "Reply")]
            for c,value in enumerate(values): self.table.setItem(i,c,QTableWidgetItem(str(value)))

    def export_csv(self):
        safe=self.target.replace("/","_").replace("\\","_")
        path,_=QFileDialog.getSaveFileName(self,"Export hop history",f"nettrace_{safe}_hop{self.hop}.csv","CSV (*.csv)")
        if not path: return
        rows=self._rows()
        export_rows=[(stamp,self.target,self.hop,address,latency,int(latency is None)) for stamp,address,latency in rows]
        write_excel_csv(path,["timestamp","target","hop","address","latency_ms","packet_loss"],export_rows)
        QMessageBox.information(self,"Hop export",f"Exported {len(export_rows)} hop samples.")

class TargetPanel(QWidget):
    alert = Signal(str)
    def __init__(self, target, interval_ms=1000, latency_limit=100, loss_limit=5):
        super().__init__()
        self.target=target; self.samples=deque(maxlen=MAX_GRAPH_POINTS); self.total=self.lost=0
        self.latency_limit=latency_limit; self.loss_limit=loss_limit; self.last_alert=0
        self.interval_ms=interval_ms; self.worker=None; self.active=False
        self.graph=LatencyGraph()
        self.stats={k:QLabel("—") for k in ("current","avg","min","max","loss","jitter")}
        self._build()
        self.restore_history()

    def restore_history(self):
        """Hydrate the graph and summary cards from persisted samples on startup."""
        try:
            with db_connect() as db:
                totals = db.execute(
                    "SELECT COUNT(*), COALESCE(SUM(packet_loss),0), AVG(latency), MIN(latency), MAX(latency) "
                    "FROM samples WHERE target=?", (self.target,)
                ).fetchone()
                rows = db.execute(
                    "SELECT timestamp,latency,packet_loss FROM samples WHERE target=? "
                    "ORDER BY id DESC LIMIT ?", (self.target, MAX_GRAPH_POINTS)
                ).fetchall()
            self.total = int(totals[0] or 0)
            self.lost = int(totals[1] or 0)
            ordered = list(reversed(rows))
            valid = [float(row[1]) for row in ordered if row[1] is not None]
            for stamp, latency, _loss in ordered:
                try:
                    ts = datetime.fromisoformat(stamp).timestamp()
                except (TypeError, ValueError):
                    ts = time.time()
                self.samples.append(float(latency) if latency is not None else None)
                self.graph.add_value(float(latency) if latency is not None else None, ts)
            if ordered:
                try:
                    self.graph.view_end = datetime.fromisoformat(ordered[-1][0]).timestamp()
                except (TypeError, ValueError):
                    self.graph.view_end = time.time()
                self.graph.follow = True
            self.stats["current"].setText(
                "Timeout" if ordered and ordered[-1][1] is None else
                (f"{float(ordered[-1][1]):.1f} ms" if ordered else "—")
            )
            self.stats["avg"].setText(f"{float(totals[2]):.1f} ms" if totals[2] is not None else "—")
            self.stats["min"].setText(f"{float(totals[3]):.1f} ms" if totals[3] is not None else "—")
            self.stats["max"].setText(f"{float(totals[4]):.1f} ms" if totals[4] is not None else "—")
            self.stats["loss"].setText(f"{100*self.lost/max(1,self.total):.1f}%" if self.total else "—")
            diffs = [abs(valid[i]-valid[i-1]) for i in range(1,len(valid))]
            self.stats["jitter"].setText(f"{statistics.mean(diffs):.1f} ms" if diffs else "—")
            self.state.setText("● Restored · stopped" if self.total else "● Stopped")
        except sqlite3.Error:
            # Preserve app startup even if an older/corrupt database needs repair.
            return

    def _build(self):
        layout=QVBoxLayout(self)
        top=QHBoxLayout(); title=QLabel(self.target); title.setStyleSheet("font-size:16px;font-weight:600;color:#e2e8f0")
        self.state=QLabel("● Stopped"); self.state.setStyleSheet("color:#94a3b8")
        top.addWidget(title); top.addStretch(); top.addWidget(self.state); layout.addLayout(top)
        grid=QGridLayout(); grid.setContentsMargins(0,2,0,2); grid.setHorizontalSpacing(6); grid.setVerticalSpacing(6)
        captions=[("Current","current"),("Average","avg"),("Minimum","min"),("Maximum","max"),("Packet loss","loss"),("Jitter","jitter")]
        for i,(caption,key) in enumerate(captions):
            card=QFrame(); card.setStyleSheet("QFrame{background:#1e293b;border:1px solid #334155;border-radius:8px}")
            v=QVBoxLayout(card); v.setContentsMargins(8,5,8,5); v.setSpacing(2); c=QLabel(caption); c.setStyleSheet("color:#94a3b8;font-size:10px")
            self.stats[key].setStyleSheet("color:#f8fafc;font-size:15px;font-weight:600")
            v.addWidget(c); v.addWidget(self.stats[key]); grid.addWidget(card,i//3,i%3)
        layout.addLayout(grid)
        graph_controls=QHBoxLayout(); graph_controls.addWidget(QLabel("Chart:")); self.graph_window=QComboBox(); self.graph_window.addItems(list(LatencyGraph.WINDOWS))
        self.graph_window.currentTextChanged.connect(lambda text:self.graph.set_window(LatencyGraph.WINDOWS[text]))
        graph_controls.addWidget(self.graph_window); graph_controls.addStretch(); layout.addLayout(graph_controls); layout.addWidget(self.graph, 1)
    def start(self):
        if self.active: return
        self.active=True; self.state.setText("● Monitoring"); self.state.setStyleSheet("color:#4ade80")
        self.worker=PingWorker(self.target,self.interval_ms); self.worker.sample.connect(self.on_sample); self.worker.start()
    def on_sample(self,target,latency,stamp):
        self.total+=1
        if latency is None: self.lost+=1
        self.samples.append(latency); self.graph.add_value(latency,time.time())
        vals=[x for x in self.samples if x is not None]
        self.stats["current"].setText("Timeout" if latency is None else f"{latency:.1f} ms")
        self.stats["avg"].setText(f"{statistics.mean(vals):.1f} ms" if vals else "—")
        self.stats["min"].setText(f"{min(vals):.1f} ms" if vals else "—")
        self.stats["max"].setText(f"{max(vals):.1f} ms" if vals else "—")
        self.stats["loss"].setText(f"{100*self.lost/self.total:.1f}%")
        diffs=[abs(vals[i]-vals[i-1]) for i in range(1,len(vals))]
        self.stats["jitter"].setText(f"{statistics.mean(diffs):.1f} ms" if diffs else "—")
        with db_connect() as db:
            db.execute("INSERT INTO samples(target,timestamp,latency,packet_loss) VALUES(?,?,?,?)",
                       (target,stamp,latency,int(latency is None)))
        loss=100*self.lost/self.total
        problem=(latency is not None and latency>=self.latency_limit) or loss>=self.loss_limit
        self.state.setText("● Warning" if problem else "● Monitoring")
        self.state.setStyleSheet("color:#fbbf24" if problem else "color:#4ade80")
        now=time.time()
        if problem and now-self.last_alert>60:
            self.last_alert=now
            reason=f"latency {latency:.1f} ms" if latency is not None and latency>=self.latency_limit else f"packet loss {loss:.1f}%"
            self.alert.emit(f"{target}: threshold exceeded ({reason}).")
    def stop(self):
        self.active=False
        if self.worker:
            self.worker.stop()
            if self.worker.isRunning(): self.worker.wait(3000)
        self.state.setText("● Stopped"); self.state.setStyleSheet("color:#94a3b8")

def tcp_connect_once(host,port,timeout=2.0):
    import socket
    start=time.perf_counter()
    try:
        with socket.create_connection((host,int(port)),timeout=timeout): return (time.perf_counter()-start)*1000
    except (OSError,ValueError,TimeoutError): return None

class TCPWorker(QThread):
    sample=Signal(str,int,object,str)
    def __init__(self,host,port,interval_ms=1000):
        super().__init__(); self.host=host; self.port=int(port); self.interval_ms=interval_ms; self.running=True
    def stop(self): self.running=False
    def run(self):
        while self.running:
            t=time.monotonic(); v=tcp_connect_once(self.host,self.port)
            self.sample.emit(self.host,self.port,v,datetime.now().isoformat(timespec="milliseconds"))
            deadline=time.monotonic()+max(0,self.interval_ms-int((time.monotonic()-t)*1000))/1000
            while self.running and time.monotonic()<deadline: self.msleep(30)

class TCPPanel(QWidget):
    def __init__(self,host,port,interval_ms=1000):
        super().__init__(); self.host=host; self.port=int(port); self.samples=deque(maxlen=3600); self.total=self.lost=0
        self.icmp_values=deque(maxlen=3600); self.graph=LatencyGraph("TCP connect"); self.stats={k:QLabel("—") for k in ("tcp","icmp","avg","loss","state")}
        self.interval_ms=interval_ms; self.worker=None; self.ping_worker=None; self.active=False; self._build()
    def _build(self):
        layout=QVBoxLayout(self); title=QLabel(f"TCP monitor · {self.host}:{self.port}"); title.setStyleSheet("font-size:18px;font-weight:600;color:#e2e8f0"); layout.addWidget(title)
        grid=QGridLayout(); labels=[("TCP connect","tcp"),("ICMP ping","icmp"),("TCP average","avg"),("TCP failure rate","loss"),("Connection status","state")]
        for i,(caption,key) in enumerate(labels):
            card=QFrame(); card.setStyleSheet("QFrame{background:#1e293b;border:1px solid #334155;border-radius:8px}"); v=QVBoxLayout(card); cap=QLabel(caption); v.setContentsMargins(8,5,8,5); v.setSpacing(2); cap.setStyleSheet("color:#94a3b8;font-size:10px"); self.stats[key].setStyleSheet("color:#f8fafc;font-size:15px;font-weight:600"); v.addWidget(cap); v.addWidget(self.stats[key]); grid.addWidget(card,i//3,i%3)
        layout.addLayout(grid); controls=QHBoxLayout(); controls.addWidget(QLabel("Chart:")); self.window=QComboBox(); self.window.addItems(list(LatencyGraph.WINDOWS)); self.window.currentTextChanged.connect(lambda x:self.graph.set_window(LatencyGraph.WINDOWS[x])); controls.addWidget(self.window); controls.addStretch(); layout.addLayout(controls); layout.addWidget(self.graph, 1)
        note=QLabel("Chart shows TCP connect time. ICMP ping is measured simultaneously for comparison."); note.setStyleSheet("color:#94a3b8"); layout.addWidget(note)
    def start(self):
        if self.active: return
        self.active=True; self.worker=TCPWorker(self.host,self.port,self.interval_ms); self.worker.sample.connect(self.on_tcp)
        self.ping_worker=PingWorker(self.host,self.interval_ms); self.ping_worker.sample.connect(self.on_ping); self.worker.start(); self.ping_worker.start()
        self.stats["state"].setText("Monitoring")
    def on_ping(self,host,value,stamp):
        self.icmp_values.append((time.time(),value)); self.stats["icmp"].setText("Timeout" if value is None else f"{value:.2f} ms")
    def on_tcp(self,host,port,value,stamp):
        ts=time.time(); self.total+=1; self.lost+=int(value is None); self.samples.append(value); valid=[x for x in self.samples if x is not None]
        self.stats["tcp"].setText("Timeout" if value is None else f"{value:.2f} ms"); self.stats["avg"].setText(f"{statistics.mean(valid):.2f} ms" if valid else "—")
        self.stats["loss"].setText(f"{100*self.lost/self.total:.1f}%"); self.stats["state"].setText("Success" if value is not None else "Failed"); self.graph.add_value(value,ts)
        icmp=self.icmp_values[-1][1] if self.icmp_values else None
        with db_connect() as db:
            db.execute("INSERT INTO tcp_samples(target,port,timestamp,connect_ms,success) VALUES(?,?,?,?,?)",(host,port,stamp,value,int(value is not None)))
            db.execute("INSERT INTO comparison_samples(target,port,timestamp,icmp_ms,tcp_ms) VALUES(?,?,?,?,?)",(host,port,stamp,icmp,value))
    def stop(self):
        self.active=False
        for worker in (self.worker,self.ping_worker):
            if worker:
                worker.stop()
                if worker.isRunning(): worker.wait(2500)
        self.stats["state"].setText("Stopped")

class HistoryDialog(QDialog):
    def __init__(self,parent,target):
        super().__init__(parent); self.setWindowTitle(f"History · {target}"); self.resize(1100,760)
        layout=QVBoxLayout(self); layout.setSpacing(12)
        controls=QHBoxLayout(); controls.addWidget(QLabel("Time range:"))
        self.period=QComboBox(); self.period.addItems(["Last 24 hours","Last 7 days","Last 30 days","All time"])
        controls.addWidget(self.period); controls.addWidget(QLabel("Chart zoom (hours):"))
        self.zoom=QSpinBox(); self.zoom.setRange(1,24); self.zoom.setValue(24); self.zoom.setSuffix(" h"); controls.addWidget(self.zoom)
        self.refresh=QPushButton("Refresh"); controls.addWidget(self.refresh); self.export=QPushButton("Export CSV"); controls.addWidget(self.export); self.delete_history=QPushButton("Delete history"); self.delete_history.setObjectName("Danger"); controls.addWidget(self.delete_history); controls.addStretch()
        layout.addLayout(controls)
        self.graph=LatencyGraph("Historical ICMP latency"); self.graph.values=deque(maxlen=100000); self.graph.set_window(86400); layout.addWidget(self.graph, 2)
        helptext=QLabel("Mouse wheel: zoom around cursor · Drag: pan through time · Zoom selector: 1–24 hours")
        helptext.setStyleSheet("color:#94a3b8"); layout.addWidget(helptext)
        self.summary=QLabel(); self.summary.setStyleSheet("font-size:14px;color:#cbd5e1"); layout.addWidget(self.summary)
        self.table=QTableWidget(0,4); self.table.setHorizontalHeaderLabels(["Time","Samples","Avg RTT","Packet loss"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch); self.table.verticalHeader().hide(); self.table.setAlternatingRowColors(True); layout.addWidget(self.table, 1)
        self.target=target; self.refresh.clicked.connect(self.load); self.period.currentIndexChanged.connect(self.load); self.zoom.valueChanged.connect(self.set_zoom); self.export.clicked.connect(self.export_csv); self.delete_history.clicked.connect(self.delete_target_history); self.load()
    def delete_target_history(self):
        answer=QMessageBox.question(
            self, "Delete history",
            f"Delete all stored history for {self.target}? This also removes traceroute and TCP records and cannot be undone.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if answer != QMessageBox.Yes:
            return
        with db_connect() as db:
            for table in ("samples", "hop_samples", "tcp_samples", "comparison_samples"):
                db.execute(f"DELETE FROM {table} WHERE target=?", (self.target,))
        if self.parent() is not None and hasattr(self.parent(), "route_snapshots"):
            self.parent().route_snapshots.pop(self.target, None)
            self.parent().heatmap.update_data([])
        self.graph.values.clear()
        self.load()
        QMessageBox.information(self, "History deleted", f"Stored history for {self.target} was deleted.")

    def cutoff(self):
        idx=self.period.currentIndex()
        if idx==3: return None
        delta=[timedelta(hours=24),timedelta(days=7),timedelta(days=30)][idx]
        return (datetime.now()-delta).isoformat(timespec="seconds")
    def query(self):
        cutoff=self.cutoff()
        with db_connect() as db:
            if cutoff: return db.execute("SELECT substr(timestamp,1,13)||':00',COUNT(*),AVG(latency),100.0*SUM(packet_loss)/COUNT(*) FROM samples WHERE target=? AND timestamp>=? GROUP BY substr(timestamp,1,13) ORDER BY 1",(self.target,cutoff)).fetchall()
            return db.execute("SELECT substr(timestamp,1,13)||':00',COUNT(*),AVG(latency),100.0*SUM(packet_loss)/COUNT(*) FROM samples WHERE target=? GROUP BY substr(timestamp,1,13) ORDER BY 1",(self.target,)).fetchall()
    def set_zoom(self,value): self.graph.set_window(value*3600)
    def load(self):
        cutoff=self.cutoff()
        with db_connect() as db:
            if cutoff: samples=db.execute("SELECT timestamp,latency FROM samples WHERE target=? AND timestamp>=? ORDER BY timestamp",(self.target,cutoff)).fetchall()
            else: samples=db.execute("SELECT timestamp,latency FROM samples WHERE target=? ORDER BY timestamp",(self.target,)).fetchall()
        self.graph.values=deque(((datetime.fromisoformat(t).timestamp(),v) for t,v in samples),maxlen=100000); self.graph.view_end=time.time(); self.graph.set_window(self.zoom.value()*3600)
        rows=self.query(); self.table.setRowCount(len(rows))
        for r,row in enumerate(rows):
            vals=[row[0],str(row[1]),f"{row[2]:.2f} ms" if row[2] is not None else "—",f"{row[3]:.2f}%" if row[3] is not None else "—"]
            for c,v in enumerate(vals): self.table.setItem(r,c,QTableWidgetItem(v))
        total=sum(x[1] for x in rows); valid=[v for _,v in samples if v is not None]; loss=sum(v is None for _,v in samples)
        self.summary.setText(f"{len(samples):,} raw samples · Average {statistics.mean(valid):.2f} ms" if valid else f"{len(samples):,} raw samples · no successful pings")
    def export_csv(self):
        path,_=QFileDialog.getSaveFileName(self,"Save history CSV",f"nettrace_history_{self.target}.csv","CSV (*.csv)")
        if not path: return
        cutoff=self.cutoff()
        with db_connect() as db:
            rows=db.execute("SELECT timestamp,latency,packet_loss FROM samples WHERE target=? AND timestamp>=? ORDER BY timestamp",(self.target,cutoff)).fetchall() if cutoff else db.execute("SELECT timestamp,latency,packet_loss FROM samples WHERE target=? ORDER BY timestamp",(self.target,)).fetchall()
        write_excel_csv(path, ["timestamp", "latency_ms", "packet_loss"], rows)
        QMessageBox.information(self,"Export complete",f"Saved {len(rows)} records.")

class SpeedtestWorker(QThread):
    status = Signal(str)
    result = Signal(float, float, float, str, str)
    error = Signal(str)

    @staticmethod
    def find_ookla_cli():
        import shutil, os, sys
        candidates = []
        # PyInstaller --onefile extracts bundled binaries into _MEIPASS.
        if getattr(sys, "_MEIPASS", None):
            candidates += [os.path.join(sys._MEIPASS, "speedtest.exe"), os.path.join(sys._MEIPASS, "speedtest")]
        app_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        candidates += [os.path.join(app_dir, "speedtest.exe"), os.path.join(app_dir, "speedtest")]
        for candidate in candidates:
            if os.path.isfile(candidate):
                return candidate
        return shutil.which("speedtest") or shutil.which("speedtest.exe")

    def run(self):
        import subprocess, json
        cli = self.find_ookla_cli()
        if not cli:
            self.error.emit(
                "Official Ookla Speedtest CLI was not found.\n\n"
                "Install the official Speedtest CLI from speedtest.net/apps/cli, "
                "or place speedtest.exe next to NetTracePro.exe (Windows).\n"
                "The test uses Ookla's automatic server selection and reports the selected server."
            )
            return
        try:
            self.status.emit("Starting official Ookla Speedtest CLI (automatic server selection)…")
            command = [cli, "--accept-license", "--accept-gdpr", "--format=json"]
            completed = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=240)
            output = (completed.stdout or "").strip()
            if completed.returncode != 0:
                detail = (completed.stderr or output or f"CLI exited with code {completed.returncode}").strip()
                raise RuntimeError(detail)
            # Some CLI builds print notices before the JSON; locate the JSON object safely.
            json_start = output.find("{")
            if json_start < 0:
                raise RuntimeError("Speedtest CLI did not return JSON output.\n" + output[:1200])
            data = json.loads(output[json_start:])
            ping_data = data.get("ping", {}) or {}
            download_data = data.get("download", {}) or {}
            upload_data = data.get("upload", {}) or {}
            ping = float(ping_data.get("latency", ping_data.get("ping", 0)))
            # Ookla CLI's JSON bandwidth is bytes/second; convert to decimal Mbps.
            down = float(download_data.get("bandwidth", 0)) * 8 / 1_000_000
            up = float(upload_data.get("bandwidth", 0)) * 8 / 1_000_000
            server = data.get("server", {}) or {}
            server_name = " · ".join(str(x) for x in [
                server.get("name"), server.get("location"), server.get("country"),
                ("ID " + str(server.get("id"))) if server.get("id") else None
            ] if x)
            if not server_name:
                server_name = "Server information not returned by CLI"
            client = data.get("interface", {}) or {}
            external_ip = client.get("externalIp") or data.get("ip")
            geo_summary = "Automatic Ookla server selection."
            if external_ip:
                geo_summary += f" Public IP: {external_ip}."
            packet_loss = data.get("packetLoss")
            if packet_loss is not None:
                geo_summary += f" Packet loss: {packet_loss}%."
            result_url = (data.get("result", {}) or {}).get("url")
            if result_url:
                geo_summary += f" Result: {result_url}"
            self.status.emit("Speedtest complete.")
            self.result.emit(ping, down, up, server_name, geo_summary)
        except subprocess.TimeoutExpired:
            self.error.emit("Speedtest timed out after 4 minutes. Please try again.")
        except Exception as exc:
            self.error.emit(
                f"Official Ookla Speedtest failed: {exc}\n\n"
                "Check that the official CLI is installed and that its first-run license prompts have been accepted."
            )

class SpeedtestDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Internet Speed Test — Speedtest.net")
        self.setMinimumSize(400, 270)
        self.resize(520, 340)
        layout = QVBoxLayout(self)
        title = QLabel("SPEEDTEST.NET")
        title.setStyleSheet("font-size: 20px; font-weight: 700; color: #38bdf8;")
        subtitle = QLabel("Automatic server selection, prioritizing your GeoIP country.")
        subtitle.setWordWrap(True); subtitle.setStyleSheet("color: #94a3b8;")
        layout.addWidget(title); layout.addWidget(subtitle)

        self.geo_label = QLabel("GeoIP: not checked yet")
        self.geo_label.setWordWrap(True)
        self.geo_label.setStyleSheet("color:#cbd5e1")
        layout.addWidget(self.geo_label)

        metrics = QGridLayout()
        self.ping_value = QLabel("—"); self.download_value = QLabel("—"); self.upload_value = QLabel("—")
        for label, value, unit in (("PING", self.ping_value, "ms"), ("DOWNLOAD", self.download_value, "Mbps"), ("UPLOAD", self.upload_value, "Mbps")):
            box = QVBoxLayout(); name = QLabel(label); name.setAlignment(Qt.AlignCenter); name.setStyleSheet("color:#94a3b8;font-size:10px;font-weight:600")
            value.setAlignment(Qt.AlignCenter); value.setStyleSheet("font-size:24px;font-weight:700")
            unit_label = QLabel(unit); unit_label.setAlignment(Qt.AlignCenter); unit_label.setStyleSheet("color:#94a3b8")
            box.addWidget(name); box.addWidget(value); box.addWidget(unit_label)
            frame = QFrame(); frame.setFrameShape(QFrame.StyledPanel); frame.setLayout(box); metrics.addWidget(frame, 0, metrics.columnCount())
        layout.addLayout(metrics)
        self.server_label = QLabel("Test server: —"); self.server_label.setWordWrap(True)
        self.status_label = QLabel("Ready to test."); self.status_label.setWordWrap(True)
        layout.addWidget(self.server_label); layout.addWidget(self.status_label)
        self.progress = QProgressBar(); self.progress.setRange(0, 0); self.progress.setVisible(False); layout.addWidget(self.progress)
        buttons = QHBoxLayout(); self.start_button = QPushButton("Start test"); self.start_button.clicked.connect(self.start_test)
        close_button = QPushButton("Close"); close_button.clicked.connect(self.close)
        buttons.addStretch(); buttons.addWidget(self.start_button); buttons.addWidget(close_button); layout.addLayout(buttons)
        self.worker = None

    def _set_busy(self, busy):
        self.start_button.setEnabled(not busy); self.progress.setVisible(busy)

    def start_test(self):
        self._set_busy(True); self.status_label.setText("Preparing test…"); self.geo_label.setText("GeoIP: detecting country…")
        self.worker = SpeedtestWorker()
        self.worker.status.connect(self.status_label.setText)
        self.worker.result.connect(self.finished_test); self.worker.error.connect(self.failed_test)
        self.worker.finished.connect(lambda: self._set_busy(False)); self.worker.start()

    def finished_test(self, ping, down, up, server, geo_summary):
        self.ping_value.setText(f"{ping:.1f}"); self.download_value.setText(f"{down:.2f}"); self.upload_value.setText(f"{up:.2f}")
        self.server_label.setText("Test server: " + server); self.geo_label.setText(geo_summary); self.status_label.setText("Test complete.")
        self.start_button.setText("Run again")

    def failed_test(self, message):
        self.geo_label.setText("Speedtest CLI: unavailable or test error.")
        self.status_label.setText(message); self.start_button.setText("Retry")

    def closeEvent(self, event):
        if self.worker is not None and self.worker.isRunning():
            event.ignore(); self.status_label.setText("Test is still running. Please wait for it to finish.")
        else: event.accept()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__(); ensure_db(); self.settings = QSettings("NetTracePro", "NetTracePro"); self.setWindowTitle("NetTrace Pro 0.7.4"); self.resize(1280, 800)
        self.setMinimumSize(680, 480)
        saved_geometry = self.settings.value("window_geometry")
        if saved_geometry:
            self.restoreGeometry(saved_geometry)
        self.setStyleSheet("""
        QMainWindow, QWidget { background:#0b1220; color:#e5edf7; font-family:Segoe UI; font-size:9pt; }
        QFrame#HeaderCard, QFrame#ControlCard { background:#111c2e; border:1px solid #24344b; border-radius:14px; }
        QLabel#Brand { color:#67d4ff; font-size:21px; font-weight:800; letter-spacing:2px; }
        QLabel#SubBrand { color:#8da4bd; font-size:9pt; }
        QLabel#SectionTitle { color:#dce8f7; font-size:11pt; font-weight:700; }
        QLabel#Muted { color:#91a4bc; }
        QPushButton { background:#26364c; color:#eaf2fb; border:1px solid #354a63; border-radius:9px; padding:5px 8px; font-weight:600; }
        QPushButton:hover { background:#324962; border-color:#4b6988; }
        QPushButton:pressed { background:#1c2b3d; }
        QPushButton:disabled { background:#1b2635; color:#718197; border-color:#253346; }
        QPushButton#Primary { background:#087fca; border:1px solid #1495e5; color:white; padding:6px 10px; }
        QPushButton#Primary:hover { background:#1098e8; }
        QPushButton#Danger { background:#9b3443; border-color:#b74859; }
        QPushButton#Danger:hover { background:#bb4355; }
        QPushButton#Accent { background:#0d766e; border-color:#14968b; }
        QPushButton#Accent:hover { background:#119388; }
        QPushButton#Tool { background:#17263a; border-color:#2a3c54; }
        QLineEdit, QSpinBox, QComboBox { background:#101b2b; border:1px solid #2a3b52; border-radius:8px; padding:4px 7px; color:#f1f6fc; selection-background-color:#087fca; min-height:16px; }
        QLineEdit:focus, QSpinBox:focus, QComboBox:focus { border:1px solid #38a7ed; }
        QComboBox::drop-down { border:0; width:24px; }
        QGroupBox { background:#111c2e; border:1px solid #24344b; border-radius:12px; margin-top:9px; padding:7px; font-weight:700; }
        QGroupBox::title { subcontrol-origin:margin; left:12px; padding:0 5px; color:#b8cce2; }
        QTabWidget::pane { background:#101a2a; border:1px solid #26384e; border-radius:10px; top:-1px; }
        QTabBar::tab { background:#17263a; color:#95abc3; padding:6px 10px; margin:2px 2px 0 0; border:1px solid #26384e; border-bottom:0; border-top-left-radius:8px; border-top-right-radius:8px; }
        QTabBar::tab:selected { background:#10253b; color:#eaf4ff; border-color:#2d5877; }
        QTabBar::tab:hover { color:#eaf4ff; }
        QTableWidget { background:#101a2a; alternate-background-color:#152338; gridline-color:#25364b; border:1px solid #26384e; border-radius:8px; }
        QHeaderView::section { background:#17263a; color:#b9cde2; padding:5px; border:0; border-right:1px solid #26384e; }
        QStatusBar { background:#09101b; color:#8ea4bd; border-top:1px solid #1f2e41; }
        QSplitter::handle { background:#24344b; height:5px; }
        QProgressBar { background:#17263a; border:1px solid #2a3b52; border-radius:5px; text-align:center; }
        QProgressBar::chunk { background:#0b8bd1; border-radius:4px; }
        """)

        root=QWidget(); self.setCentralWidget(root); outer=QVBoxLayout(root)
        outer.setContentsMargins(8,6,8,6); outer.setSpacing(5)

        # Compact fixed header + purpose-based control tabs; no nested scrollbars.
        control_tabs=QTabWidget(); control_tabs.setObjectName("ControlTabs")
        control_tabs.setDocumentMode(True)
        control_tabs.setTabPosition(QTabWidget.North)
        self.control_tabs=control_tabs
        targets_page=QWidget(); targets_layout=QVBoxLayout(targets_page)
        targets_layout.setContentsMargins(8,8,8,8); targets_layout.setSpacing(6)
        tools_page=QWidget(); tools_layout=QVBoxLayout(tools_page)
        tools_layout.setContentsMargins(8,8,8,8); tools_layout.setSpacing(6)
        settings_page=QWidget(); settings_layout=QVBoxLayout(settings_page)
        settings_layout.setContentsMargins(8,8,8,8); settings_layout.setSpacing(6)
        control_tabs.addTab(targets_page, "Targets")
        control_tabs.addTab(tools_page, "Tools & exports")
        control_tabs.addTab(settings_page, "Settings")

        # App header: identity and primary actions, split into rows to prevent clipping.
        header_card=QFrame(); header_card.setObjectName("HeaderCard")
        header=QVBoxLayout(header_card); header.setContentsMargins(10,6,10,6); header.setSpacing(4)
        brand_row=QHBoxLayout(); brand_row.setSpacing(2)
        branding=QVBoxLayout(); branding.setSpacing(1)
        brand=QLabel("NETTRACE PRO"); brand.setObjectName("Brand")
        tagline=QLabel("Network monitoring · ICMP / TCP diagnostics"); tagline.setObjectName("SubBrand")
        branding.addWidget(brand); branding.addWidget(tagline); brand_row.addLayout(branding); brand_row.addStretch(1)
        header.addLayout(brand_row)
        actions=QHBoxLayout(); actions.setSpacing(8)
        self.start_btn=QPushButton("▶  Start monitoring"); self.start_btn.setObjectName("Primary"); self.start_btn.setToolTip("Start measurements for all open targets")
        self.start_btn.clicked.connect(self.start_monitoring)
        self.stop_btn=QPushButton("■  Stop"); self.stop_btn.setObjectName("Danger"); self.stop_btn.setEnabled(False); self.stop_btn.setToolTip("Stop all active measurements")
        self.stop_btn.clicked.connect(self.stop_monitoring)
        self.speedtest_btn=QPushButton("⚡  Speed test"); self.speedtest_btn.setObjectName("Accent"); self.speedtest_btn.setToolTip("Run the integrated Ookla Speedtest")
        self.speedtest_btn.clicked.connect(self.open_speedtest)
        for b in (self.start_btn,self.stop_btn,self.speedtest_btn):
            b.setMinimumWidth(0); b.setSizePolicy(QSizePolicy.Expanding,QSizePolicy.Fixed)
            actions.addWidget(b)
        header.addLayout(actions)
        outer.addWidget(header_card)

        # Target entry cards keep ICMP and TCP inputs separate and explicit.
        target_card=QFrame(); target_card.setObjectName("ControlCard")
        target_layout=QVBoxLayout(target_card); target_layout.setContentsMargins(9,6,9,6); target_layout.setSpacing(4)
        target_title=QLabel("Monitoring targets"); target_title.setObjectName("SectionTitle"); target_layout.addWidget(target_title)
        target_row=QHBoxLayout(); target_row.setSpacing(8)
        self.target=QLineEdit(); self.target.setPlaceholderText("ICMP target · hostname or IP"); self.target.setClearButtonEnabled(True)
        # Restore the last ICMP target as a convenience; monitoring remains manual.
        self.target.setText(self.settings.value("last_icmp_target", "", type=str))
        self.add_btn=QPushButton("＋  Add ICMP target"); self.add_btn.setObjectName("Primary"); self.add_btn.clicked.connect(self.add_target)
        target_row.addWidget(self.target,1); target_row.addWidget(self.add_btn); target_layout.addLayout(target_row)
        tcp_row=QHBoxLayout(); tcp_row.setSpacing(8)
        self.tcp_host=QLineEdit(); self.tcp_host.setPlaceholderText("TCP host or IP"); self.tcp_host.setClearButtonEnabled(True)
        self.tcp_port=QSpinBox(); self.tcp_port.setRange(1,65535); self.tcp_port.setValue(443); self.tcp_port.setPrefix("Port  "); self.tcp_port.setFixedWidth(125)
        self.add_tcp_btn=QPushButton("＋  Add TCP monitor"); self.add_tcp_btn.setObjectName("Accent"); self.add_tcp_btn.clicked.connect(self.add_tcp_target)
        tcp_row.addWidget(self.tcp_host,1); tcp_row.addWidget(self.tcp_port); tcp_row.addWidget(self.add_tcp_btn); target_layout.addLayout(tcp_row)
        targets_layout.addWidget(target_card)

        # Secondary actions grouped together; avoids the old single crowded toolbar.
        tools_card=QFrame(); tools_card.setObjectName("ControlCard")
        tools=QVBoxLayout(tools_card); tools.setContentsMargins(8,5,8,5); tools.setSpacing(4)
        tools_buttons=QHBoxLayout(); tools_buttons.setSpacing(6)
        tools_label=QLabel("Tools"); tools_label.setObjectName("Muted"); tools_buttons.addWidget(tools_label)
        self.trace_btn=QPushButton("⌁  Traceroute"); self.trace_btn.setObjectName("Tool"); self.trace_btn.clicked.connect(self.run_trace)
        self.history_btn=QPushButton("◷  History & report"); self.history_btn.setObjectName("Tool"); self.history_btn.clicked.connect(self.open_history)
        self.export_btn=QPushButton("⇩  Export CSV"); self.export_btn.setObjectName("Tool"); self.export_btn.clicked.connect(self.export_csv)
        self.pdf_btn=QPushButton("▤  Export PDF"); self.pdf_btn.setObjectName("Tool"); self.pdf_btn.clicked.connect(self.export_pdf)
        for button in (self.trace_btn,self.history_btn,self.export_btn,self.pdf_btn):
            button.setMinimumWidth(0); button.setSizePolicy(QSizePolicy.Expanding,QSizePolicy.Fixed); tools_buttons.addWidget(button)
        tools_buttons.addStretch(1); tools.addLayout(tools_buttons)
        timing_row=QHBoxLayout(); timing_row.setSpacing(6)
        self.interval=QSpinBox(); self.interval.setRange(250,10000); self.interval.setValue(1000); self.interval.setSuffix(" ms"); self.interval.setToolTip("ICMP/TCP measurement interval")
        self.trace_interval=QSpinBox(); self.trace_interval.setRange(1,600); self.trace_interval.setValue(self.settings.value("route_scan_interval", 1, type=int)); self.trace_interval.setSuffix(" s"); self.trace_interval.setToolTip("Traceroute scan interval. Scans never overlap; actual cadence depends on how long the route responds.")
        self.trace_interval.valueChanged.connect(lambda value: self.settings.setValue("route_scan_interval", value))
        timing_row.addWidget(QLabel("Ping interval")); timing_row.addWidget(self.interval); timing_row.addWidget(QLabel("Route scan")); timing_row.addWidget(self.trace_interval); timing_row.addStretch(1)
        tools.addLayout(timing_row)
        tools_layout.addWidget(tools_card)

        settings_card=QFrame(); settings_card.setObjectName("ControlCard")
        settings=QHBoxLayout(settings_card); settings.setContentsMargins(8,5,8,5); settings.setSpacing(5)
        settings_title=QLabel("Alert thresholds"); settings_title.setObjectName("Muted"); settings.addWidget(settings_title)
        self.latency_limit=QSpinBox(); self.latency_limit.setRange(1,5000); self.latency_limit.setValue(100); self.latency_limit.setSuffix(" ms")
        self.loss_limit=QSpinBox(); self.loss_limit.setRange(1,100); self.loss_limit.setValue(5); self.loss_limit.setSuffix(" %")
        settings.addWidget(QLabel("Latency ≥")); settings.addWidget(self.latency_limit); settings.addWidget(QLabel("Packet loss ≥")); settings.addWidget(self.loss_limit); settings.addStretch()
        settings_layout.addWidget(settings_card)
        targets_layout.addStretch(1); tools_layout.addStretch(1); settings_layout.addStretch(1)
        outer.addWidget(control_tabs)

        split=QSplitter(Qt.Vertical); split.setChildrenCollapsible(True); split.setHandleWidth(7)
        self.tabs=QTabWidget(); self.tabs.setTabsClosable(True); self.tabs.tabCloseRequested.connect(self.close_tab); self.tabs.setMinimumHeight(0); self.tabs.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.tabs.currentChanged.connect(self.update_target_field); split.addWidget(self.tabs)
        routebox=QGroupBox("Traceroute · route history / loss heatmap")
        routebox.setMinimumHeight(0); routebox.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        rv=QVBoxLayout(routebox); rv.setContentsMargins(6,5,6,5); rv.setSpacing(3)
        self.trace_status=QLabel("Traceroute will run when monitoring starts."); self.trace_status.setObjectName("Muted"); rv.addWidget(self.trace_status)
        self.heatmap=HopHeatmap(); self.heatmap.setMinimumHeight(0); self.heatmap.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding); self.heatmap.table.cellDoubleClicked.connect(self.open_hop_detail); rv.addWidget(self.heatmap,1)
        self.route_diagnosis=QLabel("Route diagnosis: waiting for traceroute samples.")
        self.route_diagnosis.setWordWrap(True)
        self.route_diagnosis.setMaximumHeight(58)
        self.route_diagnosis.setStyleSheet("color:#b8cce2;background:#142238;border:1px solid #2a3b52;border-radius:7px;padding:5px 8px;font-size:9px")
        rv.addWidget(self.route_diagnosis)
        split.addWidget(routebox)
        split.setStretchFactor(0, 2); split.setStretchFactor(1, 3)
        split.setCollapsible(0, True); split.setCollapsible(1, False)
        split.setSizes([360, 440])
        saved_splitter = self.settings.value("splitter_sizes")
        if saved_splitter:
            try: split.setSizes([int(x) for x in saved_splitter])
            except (TypeError, ValueError): pass
        self.central_split=split
        outer.addWidget(split,1)
        self._apply_responsive_layout()
        self.setStatusBar(QStatusBar()); self.statusBar().showMessage("Ready · measurements are stored locally in SQLite")
        self.trace_worker=None; self.last_trace_target=None; self.route_snapshots=defaultdict(lambda:deque(maxlen=MAX_ROUTE_COLUMNS))
        self.route_timer=QTimer(self); self.route_timer.timeout.connect(self.run_trace)
        # Reopen the last selected ICMP target without starting live monitoring.
        restored_target = self.settings.value("last_icmp_target", "", type=str).strip()
        if restored_target:
            self.target.setText(restored_target)
            self.add_target()
            restored_routes = list(self.route_snapshots.get(restored_target, []))
            if not restored_routes:
                restored_routes = load_route_snapshots(restored_target)
                self.route_snapshots[restored_target].extend(restored_routes)
            if restored_routes:
                self.last_trace_target = restored_target
                self.heatmap.update_data(restored_routes)
                self.route_diagnosis.setText(analyze_route_snapshots(restored_routes))
                self.trace_status.setText(f"{restored_target} · restored {len(restored_routes)} saved route scans")
            else:
                self.route_diagnosis.setText("Route diagnosis: no saved traceroute history for this target yet.")
    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._apply_responsive_layout()

    def _apply_responsive_layout(self):
        """Compact only the controls that need it; never override the user's splitter position."""
        compact = self.width() < 1050 or self.height() < 720
        if hasattr(self, "control_tabs"):
            self.control_tabs.setMaximumHeight(16777215)
            self.control_tabs.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)
        buttons = (self.start_btn, self.stop_btn, self.speedtest_btn,
                   self.trace_btn, self.history_btn, self.export_btn, self.pdf_btn,
                   self.add_btn, self.add_tcp_btn)
        for button in buttons:
            button.setMinimumWidth(0)
            button.setStyleSheet("padding:3px 5px;" if compact else "padding:5px 8px;")
        if hasattr(self, "heatmap"):
            # Keep the live columns visible on compact windows; progressively
            # hide older sample columns instead of squeezing the key statistics.
            visible_samples = 3 if self.width() < 900 else (6 if self.width() < 1200 else MAX_ROUTE_COLUMNS)
            for col in range(self.heatmap.BASE_COLUMNS, self.heatmap.BASE_COLUMNS + MAX_ROUTE_COLUMNS):
                self.heatmap.table.setColumnHidden(col, col >= self.heatmap.BASE_COLUMNS + visible_samples)
        if compact:
            self.start_btn.setText("▶ Start")
            self.stop_btn.setText("■ Stop")
            self.speedtest_btn.setText("⚡ Speed test")
        else:
            self.start_btn.setText("▶  Start monitoring")
            self.stop_btn.setText("■  Stop")
            self.speedtest_btn.setText("⚡  Speed test")

    def open_speedtest(self):
        dlg=SpeedtestDialog(self); dlg.exec()
    def start_monitoring(self):
        for i in range(self.tabs.count()):
            panel=self.tabs.widget(i)
            if isinstance(panel,(TargetPanel,TCPPanel)): panel.start()
        self.start_btn.setEnabled(False); self.stop_btn.setEnabled(True)
        self.route_timer.start(self.trace_interval.value()*1000)
        self.run_trace(); self.statusBar().showMessage(f"Monitoring started · route scan interval {self.trace_interval.value()} s")
    def stop_monitoring(self):
        self.route_timer.stop()
        for i in range(self.tabs.count()):
            panel=self.tabs.widget(i)
            if isinstance(panel,(TargetPanel,TCPPanel)): panel.stop()
        if self.trace_worker and self.trace_worker.isRunning(): self.trace_worker.wait(1500)
        self.start_btn.setEnabled(True); self.stop_btn.setEnabled(False)
        self.trace_status.setText("Monitoring stopped."); self.statusBar().showMessage("Monitoring stopped")
    def export_pdf(self):
        # Export a selected ICMP/TCP report with Qt built-in PDF writer.
        from html import escape

        panel = self.tabs.currentWidget()
        if not isinstance(panel, (TargetPanel, TCPPanel)):
            QMessageBox.information(self, "PDF export", "Select an ICMP or TCP monitor tab first.")
            return

        target = panel.target if isinstance(panel, TargetPanel) else panel.host
        label = target if isinstance(panel, TargetPanel) else f"{target}_{panel.port}"
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", label).strip("._") or "report"
        path, _ = QFileDialog.getSaveFileName(
            self, "Export PDF", f"NetTrace_{safe}.pdf", "PDF (*.pdf)"
        )
        if not path:
            return
        if not path.lower().endswith(".pdf"):
            path += ".pdf"

        try:
            if isinstance(panel, TargetPanel):
                with db_connect() as db:
                    rows = db.execute(
                        "SELECT timestamp,latency,packet_loss FROM samples "
                        "WHERE target=? ORDER BY id DESC LIMIT 5000", (panel.target,)
                    ).fetchall()
                valid = [float(r[1]) for r in rows if r[1] is not None]
                lost = sum(int(r[2] or 0) for r in rows)
                loss_pct = (100.0 * lost / len(rows)) if rows else 0.0
                summary = [
                    ("Target", panel.target),
                    ("Samples", str(len(rows))),
                    ("Packet loss", f"{loss_pct:.2f}% ({lost}/{len(rows)})" if rows else "—"),
                    ("Average latency", f"{statistics.mean(valid):.2f} ms" if valid else "—"),
                    ("Minimum latency", f"{min(valid):.2f} ms" if valid else "—"),
                    ("Maximum latency", f"{max(valid):.2f} ms" if valid else "—"),
                ]
                headers = ["Timestamp", "Latency (ms)", "Packet loss"]
                body = [
                    [r[0], f"{float(r[1]):.2f}" if r[1] is not None else "Timeout", str(r[2] or 0)]
                    for r in reversed(rows)
                ]
                report_title = "ICMP measurement report"
            else:
                with db_connect() as db:
                    rows = db.execute(
                        "SELECT timestamp,icmp_ms,tcp_ms FROM comparison_samples "
                        "WHERE target=? AND port=? ORDER BY id DESC LIMIT 5000",
                        (panel.host, panel.port)
                    ).fetchall()
                valid = [float(r[2]) for r in rows if r[2] is not None]
                lost = sum(r[2] is None for r in rows)
                loss_pct = (100.0 * lost / len(rows)) if rows else 0.0
                summary = [
                    ("Target", f"{panel.host}:{panel.port}"),
                    ("Samples", str(len(rows))),
                    ("TCP failures", f"{loss_pct:.2f}% ({lost}/{len(rows)})" if rows else "—"),
                    ("Average TCP connect", f"{statistics.mean(valid):.2f} ms" if valid else "—"),
                    ("Minimum TCP connect", f"{min(valid):.2f} ms" if valid else "—"),
                    ("Maximum TCP connect", f"{max(valid):.2f} ms" if valid else "—"),
                ]
                headers = ["Timestamp", "ICMP (ms)", "TCP connect (ms)"]
                body = [
                    [r[0], f"{float(r[1]):.2f}" if r[1] is not None else "Timeout",
                     f"{float(r[2]):.2f}" if r[2] is not None else "Timeout"]
                    for r in reversed(rows)
                ]
                report_title = "TCP measurement report"

            # Include long-term hop statistics and recent diagnostics used by the heatmap.
            hop_summary = get_hop_report_summary(target)
            route_snapshots = load_route_snapshots(target, limit=MAX_ROUTE_COLUMNS)
            route_flags = route_diagnosis_flags(route_snapshots)
            route_diagnosis = analyze_route_snapshots(route_snapshots)
            route_scan_count = len(route_snapshots)
            route_last_scan = None
            if route_snapshots:
                with db_connect() as db:
                    route_last_scan = db.execute(
                        "SELECT MAX(timestamp) FROM hop_samples WHERE target=?",
                        (target,)
                    ).fetchone()[0]

            def cell(value):
                return escape(str(value if value is not None else "—"))

            def ms(value):
                return f"{float(value):.2f} ms" if value is not None else "—"

            hop_headers = [
                "Hop", "IP / Host", "Current", "Average", "Min", "Max",
                "Jitter", "Reply loss", "Samples", "IP changes",
                "Route flag", "Flag type", "Last seen"
            ]
            hop_row_parts = []
            for item in hop_summary:
                flag_text, flag_type = route_flags.get(item["hop"], ("No flag", ""))
                css_class = {
                    "route": "flag-route",
                    "caution": "flag-caution",
                    "latency": "flag-latency",
                }.get(flag_type, "flag-none")
                values = (
                    item["hop"], item["address"], ms(item["current"]),
                    ms(item["average"]), ms(item["minimum"]), ms(item["maximum"]),
                    ms(item["jitter"]),
                    f'{item["loss_pct"]:.1f}% ({item["losses"]}/{item["samples"]})',
                    item["samples"], item["address_changes"], flag_text,
                    flag_type.upper() if flag_type else "—",
                    item.get("last_seen") or "—",
                )
                cells = "".join(f"<td>{cell(value)}</td>" for value in values)
                hop_row_parts.append(f'<tr class="{css_class}">{cells}</tr>')
            hop_rows_html = "".join(hop_row_parts)
            if not hop_rows_html:
                hop_rows_html = '<tr><td colspan="13">No traceroute hop history is available for this target.</td></tr>'
            hop_header_html = "".join(f"<th>{cell(h)}</th>" for h in hop_headers)

            route_summary = [
                ("Recent scans analyzed", route_scan_count),
                ("Last route scan", route_last_scan or "—"),
                ("Hops with active flags", len(route_flags)),
                ("Diagnostic assessment", route_diagnosis),
            ]
            route_summary_html = "".join(
                f"<tr><th>{cell(key)}</th><td>{cell(value)}</td></tr>"
                for key, value in route_summary
            )

            summary_html = "".join(
                f"<tr><th>{cell(key)}</th><td>{cell(value)}</td></tr>"
                for key, value in summary
            )
            header_html = "".join(f"<th>{cell(h)}</th>" for h in headers)
            rows_html = "".join(
                "<tr>" + "".join(f"<td>{cell(value)}</td>" for value in row) + "</tr>"
                for row in body
            )
            if not body:
                rows_html = f'<tr><td colspan="{len(headers)}">No measurements have been recorded yet.</td></tr>'

            html = f'''<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
body {{ font-family: Arial, sans-serif; color: #172033; font-size: 9pt; }}
h1 {{ color: #12345a; font-size: 20pt; margin-bottom: 3px; }}
.meta {{ color: #64748b; margin-bottom: 14px; }}
h2 {{ color: #12345a; font-size: 12pt; margin: 14px 0 6px; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ border: 0.5px solid #cbd5e1; padding: 5px; text-align: left; }}
th {{ background: #dbeafe; color: #12345a; }}
.summary th {{ width: 24%; }}
.hops {{ font-size: 6.5pt; }}
.hops th, .hops td {{ padding: 3px; }}
.flag-route td {{ background: #eaf2ff; }}
.flag-caution td {{ background: #fff4d6; }}
.flag-latency td {{ background: #fde8e8; }}
.flag-none td {{ background: #ffffff; }}
.route-assessment {{ border: 1px solid #cbd5e1; background: #f1f5f9; padding: 7px; margin: 6px 0; }}
tr {{ page-break-inside: avoid; }}
.footer {{ color: #64748b; font-size: 8pt; margin-top: 10px; }}
</style></head><body>
<h1>NetTrace Pro — {cell(report_title)}</h1>
<div class="meta">Generated: {cell(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</div>
<h2>Summary</h2><table class="summary">{summary_html}</table>
<h2>Route diagnosis</h2>
<table class="summary">{route_summary_html}</table>
<div class="route-assessment">{cell(route_diagnosis)}</div>
<h2>Traceroute hop summary (up to 10,000 latest stored hop samples)</h2>
<table class="hops"><thead><tr>{hop_header_html}</tr></thead><tbody>{hop_rows_html}</tbody></table>
<p class="footer">Route flags use the latest stored traceroute scans. ROUTE = observed IP change; CAUTION = possible ICMP filtering/rate limiting or high jitter; LATENCY = repeated RTT step or final-hop non-response. Missing replies from an intermediate router alone do not prove forwarding loss.</p>
<h2>Measurement history (up to 5,000 latest samples)</h2>
<table><thead><tr>{header_html}</tr></thead><tbody>{rows_html}</tbody></table>
<div class="footer">Generated by NetTrace Pro</div>
</body></html>'''

            writer = QPdfWriter(path)
            writer.setResolution(96)
            writer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
            writer.setPageOrientation(QPageLayout.Orientation.Landscape)
            writer.setPageMargins(QMarginsF(12, 12, 12, 12))
            writer.setTitle(f"NetTrace Pro - {label}")
            writer.setCreator("NetTrace Pro")

            document = QTextDocument()
            document.setDefaultFont(QFont("Arial", 9))
            document.setHtml(html)
            document.setPageSize(QSizeF(writer.width(), writer.height()))
            document.print_(writer)

            if not os.path.isfile(path) or os.path.getsize(path) == 0:
                raise RuntimeError("PDF file was not created or is empty.")
            QMessageBox.information(self, "PDF export", f"PDF report saved successfully.\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "PDF export", "Export failed.\n" + str(e))

    def current_panel(self):
        w=self.tabs.currentWidget(); return w if isinstance(w,TargetPanel) else None
    def update_target_field(self):
        p=self.current_panel()
        self.target.setText(p.target if p else "")
        if p:
            self.settings.setValue("last_icmp_target", p.target)
            snapshots = list(self.route_snapshots.get(p.target, []))
            if not snapshots:
                snapshots = load_route_snapshots(p.target)
                self.route_snapshots[p.target].extend(snapshots)
            if snapshots:
                self.last_trace_target = p.target
                self.heatmap.update_data(snapshots)
                self.route_diagnosis.setText(analyze_route_snapshots(snapshots))
                self.trace_status.setText(f"{p.target} · restored {len(snapshots)} saved route scans")
            else:
                self.route_diagnosis.setText("Route diagnosis: waiting for traceroute samples for this target.")
    def add_target(self):
        host=self.target.text().strip()
        if not host: return
        self.settings.setValue("last_icmp_target", host)
        for i in range(self.tabs.count()):
            if getattr(self.tabs.widget(i), "target", "").lower()==host.lower():
                self.tabs.setCurrentIndex(i); return
        panel=TargetPanel(host,self.interval.value(),self.latency_limit.value(),self.loss_limit.value())
        panel.alert.connect(self.show_alert)
        self.tabs.addTab(panel,host); self.tabs.setCurrentWidget(panel)
        if self.stop_btn.isEnabled():
            panel.start(); self.route_timer.start(self.trace_interval.value()*1000)
            self.statusBar().showMessage(f"Monitoring {host} · route scan every {self.trace_interval.value()} s")
            self.run_trace()
        else: self.statusBar().showMessage(f"Target {host} added · monitoring is stopped")
    def add_tcp_target(self):
        host=self.tcp_host.text().strip(); port=self.tcp_port.value()
        if not host: return
        label=f"{host}:{port}"
        for i in range(self.tabs.count()):
            if self.tabs.tabText(i)==label: self.tabs.setCurrentIndex(i); return
        panel=TCPPanel(host,port,self.interval.value()); self.tabs.addTab(panel,label); self.tabs.setCurrentWidget(panel)
        if self.stop_btn.isEnabled(): panel.start()
        self.statusBar().showMessage(f"TCP target {host}:{port} added")
    def close_tab(self,index):
        panel=self.tabs.widget(index)
        if panel:
            panel.stop(); self.tabs.removeTab(index); panel.deleteLater()
            if self.tabs.count()==0:
                self.route_timer.stop(); self.target.clear()
            elif self.current_panel(): self.run_trace()
    def run_trace(self):
        p=self.current_panel()
        if not p or (self.trace_worker and self.trace_worker.isRunning()): return
        self.trace_btn.setEnabled(False); self.trace_status.setText(f"Tracing {p.target}…")
        self.trace_worker=TraceWorker(p.target,20); self.trace_worker.result.connect(self.show_trace)
        self.trace_worker.finished.connect(lambda:self.trace_btn.setEnabled(True)); self.trace_worker.start()
    def show_trace(self,target,rows,message):
        stamp=datetime.now().isoformat(timespec="milliseconds")
        snap={}
        with db_connect() as db:
            for hop,address,latency,detail in rows:
                snap[hop]=(address,latency)
                db.execute("INSERT INTO hop_samples(target,timestamp,hop,address,latency) VALUES(?,?,?,?,?)",
                           (target,stamp,hop,address,latency))
        current = self.current_panel()
        if rows:
            self.last_trace_target=target
            self.route_snapshots[target].append(snap)
            if current is not None and current.target == target:
                self.heatmap.update_data(list(self.route_snapshots[target]))
                self.route_diagnosis.setText(analyze_route_snapshots(list(self.route_snapshots[target])))
        elif current is not None and current.target == target:
            self.route_diagnosis.setText(f"Route diagnosis: this scan returned no hop data. {message}")
        self.trace_status.setText(f"{target} · {message} · {stamp[11:19]}")
    def open_hop_detail(self,row,column):
        hop_item=self.heatmap.table.item(row,0)
        address_item=self.heatmap.table.item(row,1)
        target=self.last_trace_target
        if not hop_item or not address_item or not target:
            return
        try: hop=int(hop_item.text())
        except ValueError: return
        HopDetailDialog(self,target,hop,address_item.text()).exec()

    def show_alert(self,message):
        self.statusBar().showMessage("⚠ "+message,10000)
    def open_history(self):
        panel=self.tabs.currentWidget()
        if isinstance(panel, TargetPanel):
            target=panel.target
        elif isinstance(panel, TCPPanel):
            target=panel.host
        else:
            return
        HistoryDialog(self,target).exec()
    def export_csv(self):
        widget=self.tabs.currentWidget()
        if isinstance(widget,TCPPanel):
            path,_=QFileDialog.getSaveFileName(self,"Export TCP measurements",f"nettrace_tcp_{widget.host}_{widget.port}.csv","CSV (*.csv)")
            if not path: return
            with db_connect() as db:
                rows=db.execute("SELECT timestamp,target,port,tcp_ms,CASE WHEN tcp_ms IS NULL THEN 0 ELSE 1 END FROM comparison_samples WHERE target=? AND port=? ORDER BY id",(widget.host,widget.port)).fetchall()
            write_excel_csv(path, ["timestamp", "target", "port", "tcp_connect_ms", "success"], rows)
            QMessageBox.information(self,"Export complete",f"Exported {len(rows)} TCP samples."); return
        p=self.current_panel()
        if not p: return
        path,_=QFileDialog.getSaveFileName(self,"Export measurements",f"nettrace_{p.target.replace('.','_')}.csv","CSV (*.csv)")
        if not path: return
        with db_connect() as db:
            rows=db.execute("SELECT timestamp,latency,packet_loss FROM samples WHERE target=? ORDER BY id",(p.target,)).fetchall()
        write_excel_csv(path, ["timestamp", "icmp_latency_ms", "packet_loss"], rows)
        QMessageBox.information(self,"Export complete",f"Exported {len(rows)} ICMP samples.")
    def closeEvent(self,event):
        # Persist the most recently selected ICMP target for the next launch.
        panel = self.current_panel()
        if panel:
            self.settings.setValue("last_icmp_target", panel.target)
        self.settings.setValue("window_geometry", self.saveGeometry())
        if hasattr(self, "central_split"):
            self.settings.setValue("splitter_sizes", self.central_split.sizes())
        self.settings.sync()
        self.route_timer.stop()
        for i in range(self.tabs.count()):
            panel=self.tabs.widget(i)
            if isinstance(panel,(TargetPanel,TCPPanel)): panel.stop()
        if self.trace_worker and self.trace_worker.isRunning(): self.trace_worker.wait(1500)
        event.accept()

if __name__=="__main__":
    app=QApplication(sys.argv); app.setApplicationName(APP_NAME)
    window=MainWindow(); window.show(); sys.exit(app.exec())
