# idps_gui_showtime_scroll.py
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading, time, re, subprocess, os, queue, json, urllib.request, random, csv, wave, struct, math
from datetime import datetime, timedelta
from collections import deque
import winsound

# =============== CONFIG ===============
APP_TITLE = "IDPS — Sci‑Fi Demo Console"
RULE_PREFIX = "IDPS_BLOCK_"
THRESHOLD_DEFAULT = 3
BLOCK_SECONDS_DEFAULT = 1800       # 30 min
WINDOW_SECONDS = 180               # Count within last 3 min
GEOLOOKUP = True
MAP_W, MAP_H = 820, 410
ALARM_WAV = "alarm.wav"            # will auto-generate if missing
FAKE_LOG = "fake_auth.log"         # simulator writes here
STATS_WINDOW_SEC = 60              # graph window
ABOUT_TEXT = (
    "Developer: Abdulrahaman Raji\n"
    "Company: Arc Robotics\n"
    "Website: https://academicprojectworld.com/\n"
    "Email: rajialex433@gmail.com"
)

# Patterns
FAIL_RE = re.compile(r"Failed password.*from (\d+\.\d+\.\d+\.\d+)")
SCAN_RE = re.compile(r"Port scan .* from (\d+\.\d+\.\d+\.\d+)")

# =============== STATE ===============
event_q = queue.Queue()
fail_events = deque()              # (ts, ip)
scan_events = deque()              # (ts, ip)
blocked_until = {}                 # ip -> datetime
whitelist = set()
monitoring = False
stop_flag = False
playing_siren = False
protect_mode = True
stats_counts = deque()             # timestamps of alerts for per-minute graph
radar_angle = 0
# =====================================

def now(): return datetime.utcnow()

def ensure_log():
    try: open(FAKE_LOG, "a").close()
    except: pass

def admin_check():
    try:
        out = subprocess.run(["net","session"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        return "Access is denied" not in out.stdout
    except:
        return False

def run_netsh(args):
    proc = subprocess.run(["netsh","advfirewall","firewall"]+args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return proc.stdout.strip()

def firewall_block(ip):
    name_in=f"{RULE_PREFIX}{ip}_IN"; name_out=f"{RULE_PREFIX}{ip}_OUT"
    o1=run_netsh(["add","rule",f"name={name_in}","dir=in","action=block","enable=yes","profile=any",f"remoteip={ip}"])
    o2=run_netsh(["add","rule",f"name={name_out}","dir=out","action=block","enable=yes","profile=any",f"remoteip={ip}"])
    return o1+"\n"+o2

def firewall_unblock(ip):
    name_in=f"{RULE_PREFIX}{ip}_IN"; name_out=f"{RULE_PREFIX}{ip}_OUT"
    o1=run_netsh(["delete","rule",f"name={name_in}"])
    o2=run_netsh(["delete","rule",f"name={name_out}"])
    return o1+"\n"+o2

def firewall_list_rules():
    out=run_netsh(["show","rule","name=all"])
    lines=[ln for ln in out.splitlines() if RULE_PREFIX in ln]
    return "\n".join(lines) if lines else "(No IDPS rules found)"

def get_geo(ip):
    if not GEOLOOKUP: return ("Unknown", None, None)
    try:
        with urllib.request.urlopen(f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon,query") as r:
            d=json.loads(r.read().decode())
            if d.get("status")=="success":
                city=d.get("city") or ""; country=d.get("country") or ""
                lat=d.get("lat"); lon=d.get("lon")
                label=f"{city}, {country}".strip(", ")
                return (label or "Unknown", lat, lon)
    except: pass
    return ("Unknown", None, None)

def gc_events():
    cutoff=now()-timedelta(seconds=WINDOW_SECONDS)
    while fail_events and fail_events[0][0]<cutoff: fail_events.popleft()
    while scan_events and scan_events[0][0]<cutoff: scan_events.popleft()

def window_count(seq, ip):
    cutoff=now()-timedelta(seconds=WINDOW_SECONDS)
    return sum(1 for t,x in seq if x==ip and t>=cutoff)

# ---- Siren (loop) ----
def ensure_alarm_wav():
    if os.path.exists(ALARM_WAV): return
    try:
        generate_siren_wav(ALARM_WAV, duration_sec=3)
    except: pass

def start_siren():
    global playing_siren
    if playing_siren: return
    playing_siren=True
    def loop():
        if os.path.exists(ALARM_WAV):
            winsound.PlaySound(ALARM_WAV, winsound.SND_ASYNC|winsound.SND_LOOP|winsound.SND_FILENAME)
            return
        while playing_siren:
            winsound.Beep(980,300); time.sleep(0.1); winsound.Beep(1200,300); time.sleep(0.15)
    threading.Thread(target=loop,daemon=True).start()

def stop_siren():
    global playing_siren
    if not playing_siren: return
    playing_siren=False
    try: winsound.PlaySound(None,0)
    except: pass

def generate_siren_wav(path="alarm.wav", duration_sec=3, sr=44100):
    n=int(duration_sec*sr); amp=32767//3; f1,f2=800.0,1400.0
    with wave.open(path,"w") as wf:
        wf.setnchannels(1); wf.setsampwidth(2); wf.setframerate(sr)
        for i in range(n):
            t=i/sr; phase=(t/duration_sec)%1.0
            frac=phase*2 if phase<0.5 else (2-phase*2)
            f=f1+(f2-f1)*frac
            s=int(amp*math.sin(2*math.pi*f*t))
            wf.writeframesraw(struct.pack("<h",s))

# ---- Blocking with timeout ----
def block_with_timeout(ip, secs, ui_log):
    if ip in whitelist:
        ui_log(f"[{now()}] Skipped block (whitelisted): {ip}")
        return
    if not protect_mode:
        ui_log(f"[{now()}] Protect Mode OFF — alert only (no block) for {ip}")
        return
    resp=firewall_block(ip)
    until=now()+timedelta(seconds=secs)
    blocked_until[ip]=until
    ui_log(f"[{now()}] BLOCKED {ip} for {secs}s\n{resp}")
    def later():
        time.sleep(secs)
        if blocked_until.get(ip) and now()>=blocked_until[ip]:
            firewall_unblock(ip); blocked_until.pop(ip,None)
            event_q.put(("unblocked",ip,now()))
    threading.Thread(target=later,daemon=True).start()

# ---- Tail worker ----
def tail_worker(path, threshold, block_seconds, ui_log):
    ensure_log()
    try:
        with open(path,"r",encoding="utf-8",errors="ignore") as f:
            f.seek(0,os.SEEK_END)
            while monitoring and not stop_flag:
                line=f.readline()
                if not line:
                    time.sleep(0.2); continue
                m1=FAIL_RE.search(line); m2=SCAN_RE.search(line)
                if not (m1 or m2): continue
                ip=(m1 or m2).group(1)
                if ip in whitelist:
                    ui_log(f"[{now()}] Ignored whitelisted IP {ip}")
                    continue
                if ip in blocked_until and now()<blocked_until[ip]: continue

                if m1:
                    fail_events.append((now(),ip)); gc_events()
                    cnt=window_count(fail_events,ip)
                    event_q.put(("fail",ip,now(),cnt))
                    if cnt>=threshold:
                        event_q.put(("alert",ip,now(),"FAILED_LOGIN",cnt))
                        def enrich_and_act():
                            start_siren()
                            label,lat,lon=get_geo(ip)
                            event_q.put(("enrich",ip,label,lat,lon,"FAILED_LOGIN"))
                            block_with_timeout(ip, block_seconds, ui_log)
                        threading.Thread(target=enrich_and_act,daemon=True).start()

                if m2:
                    scan_events.append((now(),ip)); gc_events()
                    sc=window_count(scan_events,ip)
                    event_q.put(("scan",ip,now(),sc))
                    if sc>=max(5,threshold-1):
                        event_q.put(("alert",ip,now(),"PORT_SCAN",sc))
                        def enrich_and_act2():
                            start_siren()
                            label,lat,lon=get_geo(ip)
                            event_q.put(("enrich",ip,label,lat,lon,"PORT_SCAN"))
                            block_with_timeout(ip, block_seconds, ui_log)
                        threading.Thread(target=enrich_and_act2,daemon=True).start()
    except Exception as e:
        event_q.put(("error",str(e)))

# =============== GUI ===============
class MapPane(tk.Canvas):
    def __init__(self, parent, w, h):
        super().__init__(parent,width=w,height=h,bg="#0b0e17",highlightthickness=0)
        self.img=None; self.dots=[]; self.radar=None
        if os.path.exists("world_map.png"):
            try:
                self.img=tk.PhotoImage(file="world_map.png")
                self.create_image(w//2,h//2,image=self.img)
            except: self.draw_grid()
        else:
            self.draw_grid()
        # radar center
        self.cx, self.cy = w//2, h//2
        self.create_oval(self.cx-6,self.cy-6,self.cx+6,self.cy+6, outline="#00ffaa")

    def draw_grid(self):
        self.create_rectangle(0,0,MAP_W,MAP_H, fill="#0b0e17", outline="")
        for x in range(0,MAP_W,40): self.create_line(x,0,x,MAP_H,fill="#13233f")
        for y in range(0,MAP_H,40): self.create_line(0,y,MAP_W,y,fill="#13233f")
        self.create_text(MAP_W-10,MAP_H-10,text="MAP",fill="#1ac8ff",anchor="se",font=("Consolas",10,"bold"))

    def lonlat_to_xy(self, lon, lat):
        x=(lon+180.0)/360.0*MAP_W
        y=(90.0-float(lat))/180.0*MAP_H
        return (x,y)

    def add_dot(self, lon, lat, label=""):
        try: x,y=self.lonlat_to_xy(lon,lat)
        except: return
        r=5
        dot=self.create_oval(x-r,y-r,x+r,y+r,fill="#ff3b3b",outline="#ffaaaa")
        if label: self.create_text(x+10,y-10,text=label,fill="#e9f6ff",anchor="w",font=("Segoe UI",9))
        self.dots.append(dot)
        # pulse
        def pulse():
            grow=True; rr=r
            for _ in range(10):
                self.coords(dot,x-rr,y-rr,x+rr,y+rr); self.update_idletasks(); time.sleep(0.04)
                rr=rr+1 if grow else rr-1
                if rr>=r+4: grow=False
            self.coords(dot,x-r,y-r,x+r,y+r)
        threading.Thread(target=pulse,daemon=True).start()

    def clear_dots(self):
        for d in self.dots: self.delete(d)
        self.dots.clear()

    def sweep(self, angle_deg):
        length=min(MAP_W,MAP_H)//2 - 10
        rad=math.radians(angle_deg)
        x2=self.cx+length*math.cos(rad)
        y2=self.cy-length*math.sin(rad)
        if self.radar: self.delete(self.radar)
        self.radar=self.create_line(self.cx,self.cy,x2,y2,fill="#00ffaa",width=2)

class StatsPane(tk.Canvas):
    def __init__(self,parent,width=340,height=120):
        super().__init__(parent,width=width,height=height,bg="#0b0e17",highlightthickness=0)
        self.w=width; self.h=height

    def draw(self, timestamps, window_sec=60):
        self.delete("all")
        self.create_rectangle(0,0,self.w,self.h, fill="#0b0e17", outline="#13233f")
        nowt=time.time()
        # grid
        for x in range(0,self.w,40): self.create_line(x,0,x,self.h,fill="#13233f")
        for y in range(0,self.h,30): self.create_line(0,y,self.w,y,fill="#13233f")
        # counts per 5-second bucket
        bucket=5
        buckets=max(1, int(window_sec/bucket))
        counts=[0]*buckets
        for t in timestamps:
            dt=nowt-t
            if 0<=dt<=window_sec:
                idx=buckets-1-int(dt//bucket)
                if 0<=idx<buckets: counts[idx]+=1
        # draw bars
        bw=self.w/buckets
        for i,c in enumerate(counts):
            x0=i*bw+2; y0=self.h-2
            h=min(self.h-4, c*12)
            self.create_rectangle(x0,y0-h,x0+bw-4,y0, fill="#1ac8ff", outline="")
        self.create_text(6,6, text="ATTACKS / MINUTE", anchor="nw", fill="#cfe4ff", font=("Consolas",10,"bold"))

class IDPSGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE); self.geometry("1280x860"); self.configure(bg="#0a0a0a")

        # Auto-maximize; keep reasonable minimum
        try:
            self.state('zoomed')  # Windows maximize
        except Exception:
            sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
            self.geometry(f"{int(sw*0.9)}x{int(sh*0.9)}+20+20")
        self.minsize(1000, 700)

        self.style=ttk.Style(self); self.style.theme_use("clam")
        for k in ["TFrame","TLabel","TButton"]:
            self.style.configure(k, background="#0a0a0a", foreground="#d9e6ff")
        self.style.configure("Header.TLabel", font=("Segoe UI",18,"bold"), foreground="#7efcff")
        self.style.configure("Alarm.TLabel", font=("Consolas",28,"bold"), foreground="#ffffff", background="#225522")
        self.admin_ok=admin_check()

        # Vars
        self.threshold=tk.IntVar(value=THRESHOLD_DEFAULT)
        self.block_seconds=tk.IntVar(value=BLOCK_SECONDS_DEFAULT)
        self.log_path=tk.StringVar(value=FAKE_LOG)
        self.protect_var=tk.BooleanVar(value=True)
        self.auto_sim=tk.BooleanVar(value=False)
        self._pulse_on=False

        # Menu: Help → About Us
        menubar=tk.Menu(self)
        helpm=tk.Menu(menubar, tearoff=0)
        helpm.add_command(label="About Us", command=lambda: messagebox.showinfo("About Us", ABOUT_TEXT))
        menubar.add_cascade(label="Help", menu=helpm)
        self.config(menu=menubar)

        hdr=ttk.Label(self,text="Intrusion Detection & Prevention (IDPS)", style="Header.TLabel"); hdr.pack(pady=8)

        self.alarm_banner=ttk.Label(self,text="SYSTEM NORMAL",style="Alarm.TLabel",anchor="center")
        self.alarm_banner.pack(fill="x", padx=12, pady=6)
        self.set_alarm_state(False)

        topbar=ttk.Frame(self); topbar.pack(fill="x", padx=10)
        ttk.Label(topbar,text=f"Admin rights: {'OK' if self.admin_ok else 'Not Admin'}").pack(side="left", padx=5)
        ttk.Checkbutton(topbar, text="Protect Mode (Alert + Block)", variable=self.protect_var, command=self.on_toggle_protect).pack(side="right", padx=6)

        nb=ttk.Notebook(self); nb.pack(fill="both", expand=True, padx=10, pady=10)

        self.frame_dash=ttk.Frame(nb,padding=10); nb.add(self.frame_dash,text="Dashboard")
        self.frame_ctrl=ttk.Frame(nb,padding=10); nb.add(self.frame_ctrl,text="Controls")
        self.frame_white=ttk.Frame(nb,padding=10); nb.add(self.frame_white,text="Whitelist")
        self.frame_sim=ttk.Frame(nb,padding=10); nb.add(self.frame_sim,text="Simulator")
        self.frame_logs=ttk.Frame(nb,padding=10); nb.add(self.frame_logs,text="Logs")

        self.build_dashboard()
        self.build_controls()
        self.build_whitelist()
        self.build_simulator()
        self.build_logs()

        ensure_alarm_wav()
        self.after(150, self.poll_events)
        self.after(80, self.animate_radar)
        self.after(1000, self.refresh_stats)

    # ----- Visuals -----
    def set_alarm_state(self, danger):
        if danger:
            self.alarm_banner.configure(text="ATTACK DETECTED — ALERT ACTIVE", background="#cc0000")
            self.start_pulse(); start_siren()
        else:
            self.alarm_banner.configure(text="SYSTEM NORMAL", background="#225522")
            self.stop_pulse()
            if not blocked_until: stop_siren()

    def start_pulse(self):
        if self._pulse_on: return
        self._pulse_on=True
        def loop():
            t=0
            while self._pulse_on:
                shade=int(170+50*(0.5+0.5*((t%20)+1)/20))
                self.alarm_banner.configure(background=f"#{shade:02x}0000")
                self.update_idletasks(); time.sleep(0.05); t+=1
        threading.Thread(target=loop,daemon=True).start()

    def stop_pulse(self):
        self._pulse_on=False; self.alarm_banner.configure(background="#225522")

    # ----- Build panes -----
    def build_dashboard(self):
        # Top action buttons
        btns=ttk.Frame(self.frame_dash); btns.pack(fill="x")
        self.btn_start=ttk.Button(btns,text="▶ Start Monitoring",command=self.start_monitor)
        self.btn_stop =ttk.Button(btns,text="⏹ Stop Monitoring", command=self.stop_monitor, state="disabled")
        self.btn_silence=ttk.Button(btns,text="🔇 Silence Alarm", command=lambda: stop_siren())
        self.btn_export=ttk.Button(btns,text="📝 Export Report", command=self.export_report)
        self.btn_start.pack(side="left",padx=4); self.btn_stop.pack(side="left",padx=4)
        self.btn_silence.pack(side="left",padx=10); self.btn_export.pack(side="left",padx=10)

        # ===== Scrollable container (Canvas + VScrollbar) =====
        canvas = tk.Canvas(self.frame_dash, bg="#0a0a0a", highlightthickness=0)
        vsb = ttk.Scrollbar(self.frame_dash, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)

        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        # Frame inside the canvas that holds the real content
        wrap = ttk.Frame(canvas)
        wrap_id = canvas.create_window((0, 0), window=wrap, anchor="nw")

        # Update scroll region when inner frame changes
        def _on_configure(event):
            canvas.configure(scrollregion=canvas.bbox("all"))
            # make the inner frame match the canvas width
            canvas.itemconfig(wrap_id, width=canvas.winfo_width())
        wrap.bind("<Configure>", _on_configure)

        # Mouse wheel scrolling (Windows)
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        canvas.bind_all("<MouseWheel>", _on_mousewheel)

        # ======= Actual dashboard content goes into "wrap" =======
        # Upper row: map (left) + table (right)
        upper = ttk.Frame(wrap); upper.pack(fill="both", expand=True, pady=6)

        # Map + radar
        left=ttk.Frame(upper); left.pack(side="left", padx=4, pady=4)
        self.map=MapPane(left, MAP_W, MAP_H); self.map.pack()

        # Table (scrollable) + quick actions
        right = ttk.Frame(upper); right.pack(side="left", fill="both", expand=True, padx=6)
        tbl_frame = ttk.Frame(right); tbl_frame.pack(fill="both", expand=True)

        ysb = ttk.Scrollbar(tbl_frame, orient="vertical")
        xsb = ttk.Scrollbar(tbl_frame, orient="horizontal")

        self.tree = ttk.Treeview(
            tbl_frame,
            columns=("ip","time","type","count","geo","status"),
            show="headings",
            height=18,
            yscrollcommand=ysb.set,
            xscrollcommand=xsb.set
        )
        ysb.config(command=self.tree.yview); xsb.config(command=self.tree.xview)
        ysb.pack(side="right", fill="y"); xsb.pack(side="bottom", fill="x")
        self.tree.pack(side="left", fill="both", expand=True)

        for c,w in [("ip",160),("time",180),("type",110),("count",70),("geo",250),("status",110)]:
            self.tree.heading(c, text=c.upper()); self.tree.column(c, width=w, anchor="center")

        qa = ttk.Frame(right); qa.pack(fill="x", pady=4)
        ttk.Button(qa, text="Unblock Selected", command=self.unblock_selected).pack(side="left", padx=4)
        ttk.Button(qa, text="List IDPS Rules", command=self.list_rules_popup).pack(side="left", padx=4)

        # Lower row: Attacks / Minute chart (now scrolls into view if small screen)
        bottom = ttk.Frame(wrap); bottom.pack(fill="x", pady=8)
        self.stats=StatsPane(bottom, width=MAP_W, height=130); self.stats.pack()

    def build_controls(self):
        frm=self.frame_ctrl
        r1=ttk.Frame(frm); r1.pack(fill="x", pady=6)
        ttk.Label(r1,text="Log source file:").pack(side="left")
        ttk.Entry(r1,textvariable=self.log_path,width=70).pack(side="left",padx=6)
        ttk.Button(r1,text="Use fake_auth.log",command=lambda:self.log_path.set(FAKE_LOG)).pack(side="left",padx=4)

        r2=ttk.Frame(frm); r2.pack(fill="x", pady=6)
        ttk.Label(r2,text="THRESHOLD (fails):").pack(side="left")
        ttk.Spinbox(r2,from_=1,to=50,textvariable=self.threshold,width=6).pack(side="left",padx=6)
        ttk.Label(r2,text="BLOCK TIME (seconds):").pack(side="left")
        ttk.Spinbox(r2,from_=60,to=86400,textvariable=self.block_seconds,width=10).pack(side="left",padx=6)

        r3=ttk.Frame(frm); r3.pack(fill="x", pady=6)
        ttk.Button(r3,text="Delete ALL IDPS Rules (cleanup)",command=self.cleanup_rules).pack(side="left",padx=4)

        r4=ttk.Frame(frm); r4.pack(fill="x", pady=10)
        ttk.Label(r4,text="Note: Firewall actions require Administrator.",foreground="#ffcc66").pack(anchor="w")

    def build_whitelist(self):
        frm=self.frame_white
        ttk.Label(frm,text="Add IP to Whitelist (never blocked):").pack(anchor="w")
        row=ttk.Frame(frm); row.pack(fill="x",pady=6)
        self.wh_ip_var=tk.StringVar()
        ttk.Entry(row,textvariable=self.wh_ip_var,width=24).pack(side="left",padx=6)
        ttk.Button(row,text="Add",command=self.add_whitelist).pack(side="left")
        ttk.Button(row,text="Remove",command=self.remove_whitelist).pack(side="left",padx=6)
        self.wl_list=tk.Listbox(frm,height=12); self.wl_list.pack(fill="both",expand=True,pady=6)

    def build_simulator(self):
        frm=self.frame_sim
        ttk.Label(frm,text="Simulate attacks for demo").pack(anchor="w",pady=2)

        # Auto-sim toggle
        rowa=ttk.Frame(frm); rowa.pack(fill="x",pady=6)
        self.auto_sim=tk.BooleanVar(value=False)
        ttk.Checkbutton(rowa,text="Auto Attack Simulation (random events every few seconds)",variable=self.auto_sim,command=self.toggle_auto_sim).pack(side="left")

        # Failed login
        s1=ttk.LabelFrame(frm,text="Failed‑Login Spammer"); s1.pack(fill="x",pady=6)
        r1=ttk.Frame(s1); r1.pack(fill="x",pady=4)
        self.sim_ip=tk.StringVar(value="192.168.1.100"); self.sim_times=tk.IntVar(value=3)
        ttk.Label(r1,text="IP:").pack(side="left"); ttk.Entry(r1,textvariable=self.sim_ip,width=18).pack(side="left",padx=6)
        ttk.Label(r1,text="Times:").pack(side="left"); ttk.Spinbox(r1,from_=1,to=50,textvariable=self.sim_times,width=6).pack(side="left",padx=6)
        ttk.Button(r1,text="Simulate Failed Logins →",command=self.sim_failed).pack(side="left",padx=8)

        # Port scan
        s2=ttk.LabelFrame(frm,text="Test Port Scan"); s2.pack(fill="x",pady=6)
        r2=ttk.Frame(s2); r2.pack(fill="x",pady=4)
        self.scan_base_ip=tk.StringVar(value="203.0.113."); self.scan_ips=tk.IntVar(value=5); self.scan_burst=tk.IntVar(value=10)
        ttk.Label(r2,text="Base (e.g., 203.0.113.):").pack(side="left")
        ttk.Entry(r2,textvariable=self.scan_base_ip,width=16).pack(side="left",padx=6)
        ttk.Label(r2,text="IPs:").pack(side="left"); ttk.Spinbox(r2,from_=1,to=50,textvariable=self.scan_ips,width=6).pack(side="left",padx=6)
        ttk.Label(r2,text="Burst/each:").pack(side="left"); ttk.Spinbox(r2,from_=1,to=200,textvariable=self.scan_burst,width=8).pack(side="left",padx=6)
        ttk.Button(r2,text="Fire Port Scan →",command=self.sim_scan).pack(side="left",padx=8)

    def build_logs(self):
        frm=self.frame_logs
        self.txt=tk.Text(frm,height=20,bg="#0b0e17",fg="#cfe4ff")
        self.txt.pack(fill="both",expand=True)
        btns=ttk.Frame(frm); btns.pack(fill="x",pady=6)
        ttk.Button(btns,text="Clear Log View",command=lambda:self.txt.delete("1.0","end")).pack(side="right",padx=6)

    # ----- actions -----
    def append_log(self,msg):
        self.txt.insert("end",msg+"\n"); self.txt.see("end")

    def on_toggle_protect(self):
        global protect_mode
        protect_mode=self.protect_var.get()
        self.append_log(f"[{now()}] Protect Mode set to {'ON (Alert+Block)' if protect_mode else 'OFF (Alert-only)'}")

    def start_monitor(self):
        global monitoring, stop_flag
        if monitoring: return
        path=self.log_path.get().strip()
        if not os.path.exists(path):
            try: open(path,"a").close()
            except Exception as e:
                messagebox.showerror("Error",f"Cannot open log file:\n{e}"); return
        stop_flag=False; monitoring=True
        self.set_alarm_state(False)
        self.append_log(f"[{now()}] Monitoring started: {path}")
        self.after(50, lambda: self.btn_stop.configure(state="normal"))
        self.btn_start.configure(state="disabled")
        t=threading.Thread(target=tail_worker,daemon=True,args=(path,self.threshold.get(),self.block_seconds.get(),self.append_log))
        t.start()

    def stop_monitor(self):
        global monitoring, stop_flag
        stop_flag=True; monitoring=False
        self.btn_start.configure(state="normal"); self.btn_stop.configure(state="disabled")
        self.set_alarm_state(False); self.append_log(f"[{now()}] Monitoring stopped.")

    def unblock_selected(self):
        sel=self.tree.selection()
        if not sel: messagebox.showinfo("Info","Select a row first."); return
        ip=self.tree.item(sel[0])["values"][0]
        resp=firewall_unblock(ip); blocked_until.pop(ip,None)
        self.append_log(f"[{now()}] UNBLOCK requested for {ip}\n{resp}")
        if not blocked_until: self.set_alarm_state(False)

    def list_rules_popup(self):
        rules=firewall_list_rules()
        top=tk.Toplevel(self); top.title("IDPS Rules")
        txt=tk.Text(top,width=110,height=32,bg="#0b0e17",fg="#cfe4ff"); txt.pack(fill="both",expand=True)
        txt.insert("end",rules)

    def cleanup_rules(self):
        out=run_netsh(["show","rule","name=all"]); names=[]
        for ln in out.splitlines():
            if RULE_PREFIX in ln and "Rule Name:" in ln:
                nm=ln.split("Rule Name:",1)[1].strip(); names.append(nm)
        for nm in names: run_netsh(["delete","rule",f"name={nm}"])
        self.append_log(f"[{now()}] Deleted {len(names)} IDPS firewall rules.")
        blocked_until.clear(); self.set_alarm_state(False)

    def add_whitelist(self):
        ip=self.wh_ip_var.get().strip()
        if not ip: return
        whitelist.add(ip); self.refresh_whitelist()
        self.append_log(f"[{now()}] Whitelisted {ip}")

    def remove_whitelist(self):
        ip=self.wh_ip_var.get().strip()
        whitelist.discard(ip); self.refresh_whitelist()
        self.append_log(f"[{now()}] Removed {ip} from whitelist")

    def refresh_whitelist(self):
        self.wl_list.delete(0,"end")
        for ip in sorted(whitelist): self.wl_list.insert("end",ip)

    def sim_failed(self):
        ip=self.sim_ip.get().strip(); n=int(self.sim_times.get())
        try:
            with open(FAKE_LOG,"a") as f:
                for _ in range(n):
                    f.write(f"{datetime.now()} Failed password for invalid user test from {ip}\n")
            self.append_log(f"[{now()}] Simulator wrote {n} failed‑login lines for {ip}")
        except Exception as e: messagebox.showerror("Error",str(e))

    def sim_scan(self):
        base=self.scan_base_ip.get().strip(); cnt_ips=int(self.scan_ips.get()); burst=int(self.scan_burst.get())
        try:
            with open(FAKE_LOG,"a") as f:
                for _ in range(cnt_ips):
                    last=random.randint(1,254); ip=f"{base}{last}"
                    for _ in range(burst): f.write(f"{datetime.now()} Port scan (SYN burst) from {ip}\n")
            self.append_log(f"[{now()}] Simulator fired port‑scan burst: {cnt_ips} IPs × {burst}")
        except Exception as e: messagebox.showerror("Error",str(e))

    def toggle_auto_sim(self):
        if self.auto_sim.get():
            self.append_log(f"[{now()}] Auto Simulation: ON")
            self.after(500, self.auto_sim_tick)
        else:
            self.append_log(f"[{now()}] Auto Simulation: OFF")

    def auto_sim_tick(self):
        if not self.auto_sim.get(): return
        try:
            with open(FAKE_LOG,"a") as f:
                if random.random()<0.6:
                    ip=f"198.51.100.{random.randint(2,250)}"
                    n=random.randint(2,5)
                    for _ in range(n): f.write(f"{datetime.now()} Failed password for demo from {ip}\n")
                else:
                    ip=f"203.0.113.{random.randint(2,250)}"
                    for _ in range(random.randint(6,12)): f.write(f"{datetime.now()} Port scan (SYN burst) from {ip}\n")
        except: pass
        self.after(random.randint(2000,5000), self.auto_sim_tick)

    def export_report(self):
        rows=[]
        for iid in self.tree.get_children():
            vals=self.tree.item(iid)["values"]
            if vals: rows.append(vals)
        if not rows:
            messagebox.showinfo("Export","No events to export yet."); return

        csv_path=filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")], initialfile="idps_report.csv")
        if csv_path:
            with open(csv_path,"w",newline="",encoding="utf-8") as fp:
                w=csv.writer(fp); w.writerow(["IP","Time","Type","Count","Geo","Status"]); w.writerows(rows)
        html_path=os.path.splitext(csv_path)[0]+".html" if csv_path else filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML","*.html")], initialfile="idps_report.html")
        if html_path:
            with open(html_path,"w",encoding="utf-8") as fp:
                fp.write("<html><head><meta charset='utf-8'><title>IDPS Report</title>")
                fp.write("<style>body{font-family:Segoe UI;background:#0b0e17;color:#eaf2ff;}table{border-collapse:collapse;width:100%;}th,td{border:1px solid #22324a;padding:8px;}th{background:#12223a;}</style></head><body>")
                fp.write(f"<h2>IDPS Report — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</h2>")
                fp.write("<table><tr><th>IP</th><th>Time</th><th>Type</th><th>Count</th><th>Geo</th><th>Status</th></tr>")
                for r in rows:
                    fp.write("<tr>"+"".join(f"<td>{str(x)}</td>" for x in r)+"</tr>")
                fp.write("</table></body></html>")
        messagebox.showinfo("Export","Report exported (CSV/HTML). You can print the HTML to PDF.")

    # ----- Loops -----
    def poll_events(self):
        try:
            while True:
                ev=event_q.get_nowait()
                kind=ev[0]
                if kind in ("fail","scan"):
                    _,ip,ts,cnt = ev
                    typ="FAILED_LOGIN" if kind=="fail" else "PORT_SCAN"
                    self.tree.insert("", "end", values=(ip, ts.strftime("%Y-%m-%d %H:%M:%S"), typ, cnt, "", "seen"))
                elif kind=="alert":
                    _,ip,ts,typ,cnt=ev
                    self.set_alarm_state(True)
                    self.tree.insert("", "end", values=(ip, ts.strftime("%Y-%m-%d %H:%M:%S"), typ, cnt, "", "ALERT"))
                    self.append_log(f"[{now()}] ALERT: {typ} — {ip} (count={cnt})")
                    # feed the ATTACKS/MINUTE chart
                    stats_counts.append(time.time())
                elif kind=="enrich":
                    _,ip,label,lat,lon,typ=ev
                    for iid in reversed(self.tree.get_children()):
                        vals=list(self.tree.item(iid)["values"])
                        if vals and vals[0]==ip and vals[4]=="":
                            vals[4]=label; vals[5]="BLOCKED" if protect_mode else "ALERT"
                            self.tree.item(iid, values=vals); break
                    if lat is not None and lon is not None:
                        self.map.add_dot(lon,lat,label)
                elif kind=="unblocked":
                    _,ip,t=ev
                    self.append_log(f"[{now()}] UNBLOCKED {ip} (timeout)")
                    if not blocked_until: self.set_alarm_state(False)
                elif kind=="error":
                    _,msg=ev; self.append_log(f"[ERROR] {msg}")
                event_q.task_done()
        except queue.Empty:
            pass
        self.after(150, self.poll_events)

    def animate_radar(self):
        global radar_angle
        radar_angle=(radar_angle+3)%360
        self.map.sweep(radar_angle)
        self.after(60, self.animate_radar)

    def refresh_stats(self):
        cutoff=time.time()-STATS_WINDOW_SEC
        while stats_counts and stats_counts[0]<cutoff:
            stats_counts.popleft()
        # draw the chart
        # Using StatsPane under Dashboard bottom frame
        # (StatsPane instance is created in build_dashboard)
        self.stats.draw(list(stats_counts), window_sec=STATS_WINDOW_SEC)
        self.after(1000, self.refresh_stats)

# =============== MAIN ===============
if __name__=="__main__":
    app=IDPSGUI()
    if not admin_check():
        messagebox.showwarning("Admin Required","Not running as Administrator.\nFirewall actions will fail.\nRight‑click Command Prompt → Run as administrator.")
    ensure_log()
    app.mainloop()
