"""Optional SMTP notifications. Credentials are kept in the OS keyring when available."""
import smtplib, threading
from email.message import EmailMessage
from PySide6.QtCore import QSettings

def send_configured_alert(message):
    settings=QSettings("NetTracePro","NetTracePro")
    if not settings.value("email_enabled",False,type=bool): return
    host=settings.value("smtp_host","",type=str); user=settings.value("smtp_user","",type=str)
    sender=settings.value("smtp_sender","",type=str); recipient=settings.value("smtp_recipient","",type=str)
    port=settings.value("smtp_port",587,type=int); tls=settings.value("smtp_tls",True,type=bool)
    if not all((host,sender,recipient)): return
    try:
        import keyring
        password=keyring.get_password("NetTracePro",user) if user else None
    except Exception: password=None
    if user and not password: return
    def worker():
        try:
            msg=EmailMessage(); msg["Subject"]="NetTrace Pro alert"; msg["From"]=sender; msg["To"]=recipient; msg.set_content(message)
            with smtplib.SMTP(host,port,timeout=12) as smtp:
                if tls: smtp.starttls()
                if user: smtp.login(user,password)
                smtp.send_message(msg)
        except Exception:
            pass
    threading.Thread(target=worker,daemon=True).start()
