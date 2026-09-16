import os,sqlite3,secrets,ipaddress,subprocess,time,threading,re,io,base64,hashlib
from datetime import datetime,timezone
from functools import wraps
from flask import Flask,render_template,request,redirect,url_for,session,flash,send_file,jsonify
import qrcode

DATA_DIR=os.getenv("DATA_DIR","/data"); os.makedirs(DATA_DIR,exist_ok=True)
DB=os.path.join(DATA_DIR,"wireguard.db")
ADMIN_USERNAME=os.getenv("ADMIN_USERNAME","admin")
ADMIN_PASSWORD=os.getenv("ADMIN_PASSWORD","change-me-now")
SECRET_KEY=os.getenv("SECRET_KEY") or secrets.token_hex(32)
WG_IFACE=os.getenv("WG_INTERFACE","wg0"); WG_PORT=int(os.getenv("WG_PORT","51820"))
WG_SUBNET=os.getenv("WG_SUBNET","10.66.66.0/24"); WG_DNS=os.getenv("WG_DNS","1.1.1.1")
WG_ENDPOINT=os.getenv("WG_ENDPOINT","")
app=Flask(__name__,template_folder="templates"); app.secret_key=SECRET_KEY

def db():
 c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c
def now(): return datetime.now(timezone.utc)
def iso(d): return d.astimezone(timezone.utc).isoformat() if d.tzinfo else d.replace(tzinfo=timezone.utc).isoformat()
def init():
 c=db(); c.execute("""CREATE TABLE IF NOT EXISTS clients(
 id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,public_key TEXT UNIQUE NOT NULL,
 private_key TEXT NOT NULL,address TEXT UNIQUE NOT NULL,dns TEXT NOT NULL,
 quota INTEGER NOT NULL DEFAULT 0,used INTEGER NOT NULL DEFAULT 0,
 last_rx INTEGER NOT NULL DEFAULT 0,last_tx INTEGER NOT NULL DEFAULT 0,
 expires_at TEXT,enabled INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL)"""); c.commit(); c.close()
init()

def cmd(args,input=None):
 p=subprocess.run(args,input=input,text=True,capture_output=True,timeout=30)
 return p.returncode,p.stdout.strip(),p.stderr.strip()

def ensure_wg():
    if not shutil_which("wg") or not shutil_which("ip"):
        raise RuntimeError("WireGuard tools unavailable")
    if cmd(["ip","link","show",WG_IFACE])[0] != 0:
        rc,_,e = cmd(["ip","link","add",WG_IFACE,"type","wireguard"])
        if rc != 0 and cmd(["ip","link","show",WG_IFACE])[0] != 0:
            raise RuntimeError("ساخت wg0 ممکن نیست؛ StackDome باید NET_ADMIN و پشتیبانی WireGuard را فعال کند.")
    key=os.path.join(DATA_DIR,"server_private.key")
    if not os.path.exists(key):
        rc,out,e=cmd(["wg","genkey"])
        if rc!=0: raise RuntimeError(e or "wg genkey failed")
        with open(key,"w") as f: f.write(out+"\n")
        os.chmod(key,0o600)
    with open(key) as f: private=f.read().strip()
    rc,pub,e=cmd(["wg","pubkey"],private+"\n")
    if rc!=0: raise RuntimeError(e or "wg pubkey failed")
    with open(os.path.join(DATA_DIR,"server_public.key"),"w") as f: f.write(pub+"\n")
    # Idempotent address setup (derived from WG_SUBNET, not hardcoded).
    net=ipaddress.ip_network(WG_SUBNET,strict=False)
    iface_addr=f"{net.network_address+1}/{net.prefixlen}"
    if cmd(["ip","-4","addr","show","dev",WG_IFACE])[1].find(iface_addr) < 0:
        rc,_,e=cmd(["ip","addr","add",iface_addr,"dev",WG_IFACE])
        if rc!=0 and "File exists" not in e: raise RuntimeError(e or "IP setup failed")
    rc,_,e=cmd(["ip","link","set",WG_IFACE,"up"])
    if rc!=0: raise RuntimeError(e or "wg0 up failed")
    rc,_,e=cmd(["wg","set",WG_IFACE,"private-key",key,"listen-port",str(WG_PORT)])
    if rc!=0: raise RuntimeError(e or "wg set failed")
    # Forwarding is required for routing but may be restricted by the host.
    cmd(["sysctl","-w","net.ipv4.ip_forward=1"])
    return pub

def shutil_which(x):
 import shutil; return shutil.which(x)
def pubkey():
 p=os.path.join(DATA_DIR,"server_public.key")
 return open(p).read().strip() if os.path.exists(p) else ensure_wg()

def address():
 net=ipaddress.ip_network(WG_SUBNET,strict=False); server_addr=str(net.network_address+1)
 c=db(); used={r["address"] for r in c.execute("select address from clients")}; c.close()
 for x in net.hosts():
  if str(x)==server_addr:continue
  if str(x) not in used:return str(x)
 raise RuntimeError("آدرس کافی نیست")
def apply_peer(r,enable):
 ensure_wg()
 if enable:
  rc,_,e=cmd(["wg","set",WG_IFACE,"peer",r["public_key"],"allowed-ips",r["address"]+"/32"])
 else: rc,_,e=cmd(["wg","set",WG_IFACE,"peer",r["public_key"],"remove"])
 if rc!=0: raise RuntimeError(e or "WireGuard peer operation failed")
def endpoint():
 return WG_ENDPOINT or request.host.split(":")[0]
def config(r):
 prefix=ipaddress.ip_network(WG_SUBNET,strict=False).prefixlen
 return f"""[Interface]
PrivateKey = {r['private_key']}
Address = {r['address']}/{prefix}
DNS = {r['dns']}

[Peer]
PublicKey = {pubkey()}
Endpoint = {endpoint()}:{WG_PORT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""
def get(cid):
 c=db(); r=c.execute("select * from clients where id=?",(cid,)).fetchone(); c.close(); return r
def auth(f):
 @wraps(f)
 def w(*a,**k): return f(*a,**k) if session.get("ok") else redirect(url_for("login"))
 return w
def expired(x):
 if not x:return False
 try:return datetime.fromisoformat(x).astimezone(timezone.utc)<=now()
 except:return True

def monitor():
 while True:
  try:
   if shutil_which("wg"):
    rc,out,_=cmd(["wg","show",WG_IFACE,"dump"])
    if rc==0:
     stats={}
     for line in out.splitlines()[1:]:
      z=line.split("\t")
      if len(z)>=8: stats[z[0]]=(int(z[6]),int(z[7]))
     c=db(); rows=c.execute("select * from clients where enabled=1").fetchall()
     for r in rows:
      rx,tx=stats.get(r["public_key"],(r["last_rx"],r["last_tx"]))
      # Counters can reset after interface restart; don't count negative deltas.
      dr=max(0,rx-r["last_rx"]); dt=max(0,tx-r["last_tx"]); used=r["used"]+dr+dt
      disable=bool(r["quota"] and used>=r["quota"]) or expired(r["expires_at"])
      c.execute("update clients set used=?,last_rx=?,last_tx=?,enabled=? where id=?",
                (used,rx,tx,0 if disable else 1,r["id"]))
      if disable:
       try: apply_peer(r,False)
       except: pass
     c.commit(); c.close()
  except Exception: pass
  time.sleep(10)
threading.Thread(target=monitor,daemon=True).start()

@app.route("/login",methods=["GET","POST"])
def login():
 if request.method=="POST":
  if secrets.compare_digest(request.form.get("username",""),ADMIN_USERNAME) and secrets.compare_digest(request.form.get("password",""),ADMIN_PASSWORD):
   session["ok"]=True; return redirect(url_for("dashboard"))
  flash("نام کاربری یا رمز عبور اشتباه است")
 return render_template("login.html")
@app.route("/logout")
def logout(): session.clear(); return redirect(url_for("login"))
@app.route("/")
@auth
def dashboard():
 try: ensure_wg(); status="فعال"
 except Exception as e: status=str(e)
 c=db(); rows=c.execute("select * from clients order by id desc").fetchall(); c.close()
 return render_template("dashboard.html",clients=rows,status=status,port=WG_PORT,subnet=WG_SUBNET,endpoint=endpoint(),server_public=pubkey() if os.path.exists(os.path.join(DATA_DIR,"server_public.key")) else "---")
@app.route("/clients/add",methods=["POST"])
@auth
def add():
 try:
  ensure_wg(); name=request.form.get("name","client").strip() or "client"; dns=request.form.get("dns","").strip() or WG_DNS
  quota_gb=float(request.form.get("quota_gb","0") or 0); quota=max(0,int(quota_gb*1024**3))
  ex=request.form.get("expires_at","").strip(); expires=None
  if ex:
   d=datetime.fromisoformat(ex); expires=iso(d)
   if expired(expires): raise ValueError("تاریخ باید آینده باشد")
  addr=address(); priv=cmd(["wg","genkey"])[1]; pub=cmd(["wg","pubkey"],priv+"\n")[1]
  rc,_,e=cmd(["wg","set",WG_IFACE,"peer",pub,"allowed-ips",addr+"/32"])
  if rc!=0: raise RuntimeError(e or "peer failed")
  c=db(); c.execute("""insert into clients(name,public_key,private_key,address,dns,quota,expires_at,created_at)
                       values(?,?,?,?,?,?,?,?)""",(name,pub,priv,addr,dns,quota,expires,iso(now()))); c.commit(); cid=c.execute("select last_insert_rowid()").fetchone()[0]; c.close()
  flash("کانفیگ واقعی ساخته شد."); return redirect(url_for("conf",cid=cid))
 except Exception as e: flash("خطا: "+str(e)); return redirect(url_for("dashboard"))
@app.route("/clients/<int:cid>/conf")
@auth
def conf(cid):
 r=get(cid)
 if not r:return "not found",404
 name=re.sub(r"[^A-Za-z0-9_.-]","_",r["name"])+".conf"
 return send_file(io.BytesIO(config(r).encode()),as_attachment=True,download_name=name,mimetype="text/plain")
@app.route("/clients/<int:cid>/qr.png")
@auth
def qr(cid):
 r=get(cid)
 if not r:return "not found",404
 b=io.BytesIO(); qrcode.make(config(r)).save(b,"PNG"); b.seek(0); return send_file(b,mimetype="image/png")
@app.route("/clients/<int:cid>/toggle",methods=["POST"])
@auth
def toggle(cid):
 r=get(cid)
 if not r:return "not found",404
 try:
  if not r["enabled"] and (expired(r["expires_at"]) or (r["quota"] and r["used"]>=r["quota"])): raise RuntimeError("حجم یا زمان کانفیگ تمام شده؛ ابتدا تمدید کنید.")
  apply_peer(r,not bool(r["enabled"]))
  c=db(); c.execute("update clients set enabled=? where id=?",(0 if r["enabled"] else 1,cid)); c.commit(); c.close()
 except Exception as e: flash("خطا: "+str(e))
 return redirect(url_for("dashboard"))
@app.route("/clients/<int:cid>/renew",methods=["POST"])
@auth
def renew(cid):
 r=get(cid)
 try:
  q=max(0,int(float(request.form.get("quota_gb","0") or 0)*1024**3)); ex=request.form.get("expires_at","").strip()
  d=datetime.fromisoformat(ex); ex=iso(d)
  if expired(ex): raise ValueError("تاریخ باید آینده باشد")
  apply_peer(r,True); c=db(); c.execute("update clients set quota=?,used=0,last_rx=0,last_tx=0,expires_at=?,enabled=1 where id=?",(q,ex,cid)); c.commit(); c.close(); flash("حجم و تاریخ تمدید شد.")
 except Exception as e: flash("تمدید ناموفق: "+str(e))
 return redirect(url_for("dashboard"))
@app.route("/clients/<int:cid>/delete",methods=["POST"])
@auth
def delete(cid):
 r=get(cid)
 if r:
  try: apply_peer(r,False)
  except: pass
  c=db(); c.execute("delete from clients where id=?",(cid,)); c.commit(); c.close()
 return redirect(url_for("dashboard"))
@app.route("/api/health")
def health():
    return jsonify(ok=True, wireguard_tools=bool(shutil_which("wg")), time=iso(now()))

# Extra unauthenticated, always-200 health endpoints. Stackdome's health
# checker convention isn't documented to us, and GET "/" 302-redirects to
# /login when logged out — some platforms only accept a bare 200, so a
# redirect there can leave the resource stuck at "checking" forever even
# though the app is actually up. These cover the common conventions.
@app.route("/health")
@app.route("/healthz")
def health_plain():
    return "ok", 200, {"Content-Type": "text/plain"}

if __name__=="__main__": app.run("0.0.0.0",5000)
