"""Optional LAN discovery and user-selected TCP port checks."""
import ipaddress, platform, re, socket, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (QDialog,QVBoxLayout,QHBoxLayout,QFormLayout,QLabel,QLineEdit,QSpinBox,QPushButton,QTableWidget,QTableWidgetItem,QHeaderView,QMessageBox,QCheckBox)
from PySide6.QtCore import QSettings
from networking import ping_once, tcp_connect_once
from database import db_connect
from process_utils import run_hidden

class DiscoveryWorker(QThread):
    progress=Signal(int,int)
    completed=Signal(list,str)
    failed=Signal(str)
    def __init__(self, subnet):
        super().__init__(); self.subnet=subnet
    def run(self):
        try:
            net=ipaddress.ip_network(self.subnet,strict=False)
            if not net.is_private: raise ValueError("Z bezpečnostních důvodů lze skenovat pouze privátní podsítě.")
            if net.num_addresses>512: raise ValueError("Rozsah je příliš velký. Zadej menší podsíť (max. 512 adres).")
            hosts=list(net.hosts())
            if not hosts: hosts=[net.network_address]
            results=[]
            def probe(ip):
                latency=ping_once(str(ip),650)
                hostname="—"
                if latency is not None:
                    try: hostname=socket.gethostbyaddr(str(ip))[0]
                    except OSError: pass
                return (str(ip),hostname,latency)
            with ThreadPoolExecutor(max_workers=48) as pool:
                futures=[pool.submit(probe,ip) for ip in hosts]
                for i,f in enumerate(as_completed(futures),1):
                    results.append(f.result()); self.progress.emit(i,len(hosts))
            # MAC addresses are best-effort: only entries already visible in OS neighbour/ARP cache.
            mac_map={}
            if platform.system().lower()=="windows":
                try:
                    out=run_hidden(["arp","-a"],capture_output=True,text=True,timeout=8).stdout
                    for line in out.splitlines():
                        m=re.search(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-f-]{17})",line,re.I)
                        if m: mac_map[m.group(1)]=m.group(2).replace("-",":").upper()
                except Exception: pass
            stamp=datetime.now().isoformat(timespec="seconds")
            rows=[]
            for ip,hostname,latency in sorted(results,key=lambda x:ipaddress.ip_address(x[0])):
                mac=mac_map.get(ip,"—"); status="Online" if latency is not None else "No reply"
                if latency is not None or mac!="—": rows.append((ip,hostname,mac,latency,status))
                with db_connect() as db:
                    db.execute("INSERT INTO device_scans(scanned_at,subnet,ip,hostname,mac,latency_ms,status) VALUES(?,?,?,?,?,?,?)",(stamp,str(net),ip,hostname,mac,latency,status))
            self.completed.emit(rows,str(net))
        except Exception as e: self.failed.emit(str(e))

class NetworkDiscoveryDialog(QDialog):
    def __init__(self,parent=None):
        super().__init__(parent); self.setWindowTitle("LAN device discovery"); self.resize(760,520)
        layout=QVBoxLayout(self); form=QHBoxLayout(); form.addWidget(QLabel("Privátní subnet (CIDR):"))
        self.subnet=QLineEdit("192.168.1.0/24"); form.addWidget(self.subnet,1)
        self.scan=QPushButton("Scan network"); self.scan.clicked.connect(self.start_scan); form.addWidget(self.scan); layout.addLayout(form)
        self.status=QLabel("Best-effort scan: MAC/hostname depend on OS cache and network permissions."); layout.addWidget(self.status)
        self.table=QTableWidget(0,5); self.table.setHorizontalHeaderLabels(["IP address","Hostname","MAC (if known)","Ping","Status"]); self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch); layout.addWidget(self.table,1)
        self.worker=None
    def start_scan(self):
        if self.worker and self.worker.isRunning(): return
        self.scan.setEnabled(False); self.table.setRowCount(0); self.status.setText("Scanning selected private subnet…")
        self.worker=DiscoveryWorker(self.subnet.text().strip()); self.worker.progress.connect(lambda a,b:self.status.setText(f"Scanning… {a}/{b}")); self.worker.completed.connect(self._on_scan_completed); self.worker.failed.connect(self.fail); self.worker.start()
    def _on_scan_completed(self,rows,net):
        self.scan.setEnabled(True); self.table.setRowCount(len(rows))
        for r,row in enumerate(rows):
            vals=[row[0],row[1],row[2],f"{row[3]:.1f} ms" if row[3] is not None else "—",row[4]]
            for c,v in enumerate(vals): self.table.setItem(r,c,QTableWidgetItem(str(v)))
        self.status.setText(f"{net}: found {len(rows)} responding/known devices. MAC data comes only from the local ARP cache; no physical topology is inferred.")
    def fail(self,msg): self.scan.setEnabled(True); QMessageBox.warning(self,"Discovery failed",msg)

class PortCheckDialog(QDialog):
    def __init__(self,parent=None):
        super().__init__(parent); self.setWindowTitle("TCP port availability check"); self.resize(600,420)
        layout=QVBoxLayout(self); form=QFormLayout(); self.host=QLineEdit("127.0.0.1"); self.ports=QLineEdit("22, 53, 80, 443, 3389"); self.ports.setPlaceholderText("Comma-separated ports, e.g. 22,80,443")
        form.addRow("Host / IP",self.host); form.addRow("Ports",self.ports); layout.addLayout(form)
        btn=QPushButton("Check ports"); btn.clicked.connect(self.check); layout.addWidget(btn)
        self.table=QTableWidget(0,3); self.table.setHorizontalHeaderLabels(["Port","Result","Connect time"]); self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch); layout.addWidget(self.table,1)
        self.note=QLabel("TCP connect tests only; an open connection does not establish that a service is secure."); layout.addWidget(self.note)
    def check(self):
        host=self.host.text().strip()
        try:
            ports=sorted(set(int(x.strip()) for x in self.ports.text().split(",") if x.strip()))
            if not host or not ports or any(p<1 or p>65535 for p in ports): raise ValueError()
        except ValueError:
            QMessageBox.warning(self,"Invalid input","Zadej host a porty 1–65535 oddělené čárkou."); return
        self.table.setRowCount(len(ports))
        for i,p in enumerate(ports):
            value=tcp_connect_once(host,p,1.5); vals=[str(p),"OPEN" if value is not None else "Closed / filtered",f"{value:.1f} ms" if value is not None else "—"]
            for c,v in enumerate(vals): self.table.setItem(i,c,QTableWidgetItem(v))


class EmailAlertDialog(QDialog):
    def __init__(self,parent=None):
        super().__init__(parent); self.setWindowTitle("Email alert settings"); self.resize(480,300)
        self.settings=QSettings("NetTracePro","NetTracePro"); layout=QVBoxLayout(self); form=QFormLayout()
        self.enabled=QCheckBox("Enable email notifications"); self.enabled.setChecked(self.settings.value("email_enabled",False,type=bool)); form.addRow(self.enabled)
        self.host=QLineEdit(self.settings.value("smtp_host","",type=str)); self.port=QSpinBox(); self.port.setRange(1,65535); self.port.setValue(self.settings.value("smtp_port",587,type=int))
        self.user=QLineEdit(self.settings.value("smtp_user","",type=str)); self.password=QLineEdit(); self.password.setEchoMode(QLineEdit.Password); self.password.setPlaceholderText("Password saved to OS keyring")
        self.sender=QLineEdit(self.settings.value("smtp_sender","",type=str)); self.recipient=QLineEdit(self.settings.value("smtp_recipient","",type=str)); self.tls=QCheckBox("Use STARTTLS"); self.tls.setChecked(self.settings.value("smtp_tls",True,type=bool))
        for label,widget in (("SMTP server",self.host),("Port",self.port),("Username",self.user),("Password",self.password),("From",self.sender),("To",self.recipient),("Security",self.tls)): form.addRow(label,widget)
        layout.addLayout(form); note=QLabel("Password is stored in the operating-system keyring (requires keyring package). Alerts are sent in background."); note.setWordWrap(True); layout.addWidget(note)
        row=QHBoxLayout(); row.addStretch(); save=QPushButton("Save"); save.clicked.connect(self.save); cancel=QPushButton("Cancel"); cancel.clicked.connect(self.reject); row.addWidget(save); row.addWidget(cancel); layout.addLayout(row)
    def save(self):
        if self.enabled.isChecked() and (not self.host.text().strip() or not self.sender.text().strip() or not self.recipient.text().strip()):
            QMessageBox.warning(self,"Missing settings","Vyplň SMTP server, From a To."); return
        for key,value in (("email_enabled",self.enabled.isChecked()),("smtp_host",self.host.text().strip()),("smtp_port",self.port.value()),("smtp_user",self.user.text().strip()),("smtp_sender",self.sender.text().strip()),("smtp_recipient",self.recipient.text().strip()),("smtp_tls",self.tls.isChecked())): self.settings.setValue(key,value)
        if self.password.text():
            try:
                import keyring
                keyring.set_password("NetTracePro",self.user.text().strip(),self.password.text())
            except Exception as e:
                QMessageBox.warning(self,"Keyring unavailable",f"Nelze bezpečně uložit heslo: {e}. Nainstaluj balíček keyring."); return
        self.settings.sync(); self.accept()
