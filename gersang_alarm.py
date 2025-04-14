import threading
import tkinter as tk
from tkinter import messagebox, filedialog, ttk
import json
import os
import re
import winsound
import psutil
import socket
from scapy.all import sniff, IP, Raw
from scapy.config import conf
import pygame  # 🔊 MP3 재생용
import time

CONFIG_FILE = "config.json"
running = False
keywords = []
selected_mp3_path = None

target_ip = "211.233.83.89"

def is_pcap_available():
    return conf.use_pcap

def get_all_interfaces():
    interfaces = []
    for name, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family.name == "AF_INET" and not addr.address.startswith("127."):
                interfaces.append(name)
                break
    return interfaces

def get_default_interface():
    gateways = psutil.net_if_addrs()
    for name, addrs in gateways.items():
        for addr in addrs:
            if addr.family.name == "AF_INET" and not addr.address.startswith("127."):
                return name
    return None

def is_interface_connected(interface_name):
    try:
        addrs = psutil.net_if_addrs().get(interface_name, [])
        ip_address = None
        for addr in addrs:
            if addr.family.name == "AF_INET":
                ip_address = addr.address
                break

        if not ip_address:
            print(f"[X] 인터페이스 {interface_name}에 유효한 IPv4 주소 없음")
            return False

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((ip_address, 0))

        try:
            s.connect(("8.8.8.8", 80))
            print(f"[O] 인터페이스 {interface_name} ({ip_address}) → 인터넷 연결 확인됨")
            return True
        except Exception as inner_err:
            print(f"[X] 인터페이스 {interface_name} → 인터넷 연결 실패: {inner_err}")
            return False
        finally:
            s.close()
    except Exception as outer_err:
        print(f"[!] 인터페이스 {interface_name} 연결 체크 중 예외 발생: {outer_err}")
        return False

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError:
            pass
    return {"keywords": "봉돌,불깃,팜,팝니다,삼,삽니다"}

def save_config(keywords):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump({"keywords": keywords}, f, ensure_ascii=False, indent=2)

def alert():
    if alarm_mode_var.get() == "MP3 파일" and selected_mp3_path:
        try:
            pygame.mixer.init()
            pygame.mixer.music.load(selected_mp3_path)
            pygame.mixer.music.play()

            # 재생 시간 제한
            duration_sec = int(alarm_duration_var.get())
            time.sleep(duration_sec)
            pygame.mixer.music.stop()

        except Exception as e:
            chat_log_text.insert(tk.END, f"[!] MP3 재생 실패: {e}\n기본 알림음으로 대체합니다.\n", "keyword")
            chat_log_text.see(tk.END)
            if os.name == "nt":
                winsound.Beep(1000, int(alarm_duration_var.get()) * 1000)
            else:
                os.system('say "포함된 글이 있습니다."')
    else:
        if os.name == "nt":
            winsound.Beep(1000, int(alarm_duration_var.get()) * 1000)
        else:
            os.system('say "포함된 글이 있습니다."')


def on_alarm_mode_change(event=None):
    if alarm_mode_var.get() == "MP3 파일":
        mp3_button.config(state=tk.NORMAL)
        mp3_label.config(fg="black")
    else:
        mp3_button.config(state=tk.DISABLED)
        mp3_label.config(fg="gray")


def find_matching_keywords(nickname, content):
    return [kw for kw in keywords if kw in nickname or kw in content]

def is_valid_hex_packet(hex_data):
    return re.match(r"^4b0000821f0000", hex_data) is not None

def decode_hex_payload(hex_data):
    try:
        nickname = hex_data[14:14+40]
        content = hex_data[14+42:14+42+80]
        decoded_nickname = bytes.fromhex(nickname).decode("euc-kr", errors="ignore").replace("\x00", "").strip()
        decoded_content = bytes.fromhex(content).decode("euc-kr", errors="ignore").replace("\x00", "").strip()
        return {"nickname": decoded_nickname, "content": decoded_content}
    except Exception as e:
        return {"nickname": "", "content": f"복호화 실패: {e}"}

processed_packets = set()

def process_packet(packet):
    if not running:
        return

    if IP in packet and Raw in packet:
        raw_data = packet[Raw].load.hex()

        packet_hash = hash(raw_data)
        if packet_hash in processed_packets:
            return
        processed_packets.add(packet_hash)

        if len(processed_packets) > 10000:
            processed_packets.clear()

        if is_valid_hex_packet(raw_data):
            decoded = decode_hex_payload(raw_data)
            nickname = decoded['nickname']
            content = decoded['content']
            log = f"[{nickname}] {content}\n\n"

            matched = find_matching_keywords(nickname, content)
            if matched:
                chat_log_text.insert(tk.END, f"🚨 포함된 키워드: {', '.join(matched)}\n", "keyword")
                chat_log_text.insert(tk.END, log, "keyword")
                alert()
                trim_chat_log()
            else:
                chat_log_text.insert(tk.END, log)
                trim_chat_log()

            chat_log_text.see(tk.END)

def start_sniffing():
    global running, keywords
    if running:
        return
    running = True

    keyword_input = keyword_entry.get().strip()
    keywords = keyword_input.split(",") if keyword_input else []
    save_config(keyword_input)

    start_button.config(state=tk.DISABLED)
    stop_button.config(state=tk.NORMAL)
    keyword_entry.config(state=tk.DISABLED)
    interface_dropdown.config(state=tk.DISABLED)
    alarm_mode_dropdown.config(state=tk.DISABLED)
    alarm_duration_dropdown.config(state=tk.DISABLED)
    mp3_button.config(state=tk.DISABLED)

    iface = interface_var.get()

    if not iface:
        messagebox.showerror("인터페이스 오류", "인터페이스가 선택되지 않았습니다.")
        running = False
        start_button.config(state=tk.readonly)
        stop_button.config(state=tk.DISABLED)
        keyword_entry.config(state=tk.readonly)
        interface_dropdown.config(state=tk.readonly)
        return

    if not is_interface_connected(iface):
        messagebox.showerror("인터넷 연결 오류", f"선택한 인터페이스 [{iface}]는 인터넷에 연결되어 있지 않습니다.")
        running = False
        start_button.config(state=tk.readonly)
        stop_button.config(state=tk.DISABLED)
        keyword_entry.config(state=tk.readonly)
        interface_dropdown.config(state=tk.readonly)
        return

    sniff_thread = threading.Thread(
        target=sniff,
        kwargs={
            "iface": iface,
            "filter": "ip",
            "prn": process_packet,
            "store": 0
        }
    )
    sniff_thread.daemon = True
    sniff_thread.start()

def stop_sniffing():
    global running
    running = False
    start_button.config(state=tk.NORMAL)
    stop_button.config(state=tk.DISABLED)
    keyword_entry.config(state=tk.NORMAL)
    interface_dropdown.config(state="readonly")
    alarm_mode_dropdown.config(state="readonly")
    alarm_duration_dropdown.config(state="readonly")
    #mp3 선택 상태면 mp3 버튼 활성화
    if alarm_mode_var.get() == "MP3 파일":
        mp3_button.config(state=tk.NORMAL)

MAX_LINES = 1000

def trim_chat_log():
    lines = int(chat_log_text.index('end-1c').split('.')[0])
    if lines > MAX_LINES:
        chat_log_text.delete("1.0", f"{lines - MAX_LINES}.0")

def load_mp3_file():
    global selected_mp3_path
    file_path = filedialog.askopenfilename(filetypes=[("MP3 files", "*.mp3")])
    if file_path:
        selected_mp3_path = file_path
        mp3_label.config(text=os.path.basename(file_path))

# ---------------- GUI ----------------
root = tk.Tk()
root.title("사통팔달 키워드 감시 도구")
alarm_duration_var = tk.StringVar(value="3")  # 기본값: 3초


config = load_config()

tk.Label(root, text="감시할 키워드 (콤마로 구분)").pack()
keyword_entry = tk.Entry(root, width=50)
keyword_entry.pack(padx=10, pady=2)
keyword_entry.insert(0, config["keywords"])

made_by_label = tk.Label(root, text="Made by: 신구섭 돈좀..", font=("맑은 고딕", 8), fg="gray")
made_by_label.pack(side=tk.TOP, anchor=tk.SE, padx=5, pady=5)

alarm_frame = tk.Frame(root)
alarm_frame.pack(padx=10, pady=5, fill=tk.X)

tk.Label(alarm_frame, text="알람 길이 (초):").pack(side=tk.LEFT)

alarm_duration_dropdown = ttk.Combobox(
    alarm_frame,
    textvariable=alarm_duration_var,
    values=[str(i) for i in range(1, 11)],
    state="readonly",
    width=5
)
alarm_duration_dropdown.pack(side=tk.LEFT, padx=5)


alarm_mode_var = tk.StringVar(value="기본음")  # 기본값: 기본음

alarm_mode_frame = tk.Frame(root)
alarm_mode_frame.pack(padx=10, pady=2, fill=tk.X)

tk.Label(alarm_mode_frame, text="알림음 종류:").pack(side=tk.LEFT)

alarm_mode_dropdown = ttk.Combobox(
    alarm_mode_frame, textvariable=alarm_mode_var,
    values=["기본음", "MP3 파일"], state="readonly", width=10
)
alarm_mode_dropdown.pack(side=tk.LEFT)
alarm_mode_dropdown.bind("<<ComboboxSelected>>", on_alarm_mode_change)


mp3_button = tk.Button(alarm_frame, text="🔊 MP3 파일 선택", command=load_mp3_file)
mp3_button.pack(side=tk.LEFT, padx=5)

mp3_label = tk.Label(alarm_frame, text="기본 알람 사용 중", font=("맑은 고딕", 8))
mp3_label.pack(side=tk.LEFT, padx=5)

on_alarm_mode_change()  # 초기화 시 모드 반영

interface_frame = tk.Frame(root)
interface_frame.pack(padx=10, pady=10, fill=tk.X)

tk.Label(interface_frame, text="인터페이스 선택:").pack(side=tk.LEFT)

interface_var = tk.StringVar()
available_interfaces = get_all_interfaces()
default_iface = get_default_interface()
interface_var.set(default_iface if default_iface in available_interfaces else "")

interface_dropdown = ttk.Combobox(interface_frame, textvariable=interface_var, values=available_interfaces, state="readonly", width=25)
interface_dropdown.pack(side=tk.LEFT, padx=5)

button_frame = tk.Frame(interface_frame)
button_frame.pack(side=tk.RIGHT)

start_button = tk.Button(button_frame, text="▶ 감시 시작", command=start_sniffing, state=tk.NORMAL, width=10)
start_button.pack(side=tk.TOP, padx=5, pady=2)

stop_button = tk.Button(button_frame, text="◼ 감시 중지", command=stop_sniffing, state=tk.DISABLED, width=10)
stop_button.pack(side=tk.TOP, padx=5, pady=2)

chat_log_frame = tk.Frame(root)
chat_log_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

scrollbar = tk.Scrollbar(chat_log_frame)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

chat_log_text = tk.Text(chat_log_frame, height=15, width=70, yscrollcommand=scrollbar.set, wrap=tk.WORD)
chat_log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
chat_log_text.tag_config("keyword", foreground="red", font=("맑은 고딕", 10, "bold"))

scrollbar.config(command=chat_log_text.yview)

if not is_pcap_available():
    messagebox.showerror(
        "패킷 캡처 드라이버 필요",
        "이 프로그램은 패킷 캡처를 위해 Npcap 또는 WinPcap이 필요합니다.\n\n"
        "아래 링크에서 Npcap을 설치해 주세요:\n"
        "https://nmap.org/npcap/\n\n"
        "설치 후 프로그램을 다시 실행해 주세요."
    )
    import webbrowser
    webbrowser.open("https://nmap.org/npcap/")
    root.destroy()
    exit()

root.mainloop()
