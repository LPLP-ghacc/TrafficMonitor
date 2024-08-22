import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from scapy.all import sniff, get_if_list, hexdump, Packet, conf
from scapy.layers.inet import IP, TCP, UDP
import psutil
import time

# Глобальные переменные для управления захватом и потоками
stop_sniffing_flag = threading.Event()
sniff_threads = []
captured_packets = {}
process_packets = {}
update_lock = threading.Lock()

# Пояснения для наиболее часто используемых полей
field_descriptions = {
    "src": "Source IP address",
    "dst": "Destination IP address",
    "sport": "Source port",
    "dport": "Destination port",
    "seq": "Sequence number",
    "ack": "Acknowledgment number",
    "dataofs": "Data offset",
    "flags": "TCP flags",
    "window": "Window size",
    "chksum": "Checksum",
    "urgptr": "Urgent pointer"
}

def get_process_info(sport, dport):
    """
    Получить информацию о процессе по исходному и целевому портам
    """
    for conn in psutil.net_connections(kind='inet'):
        if conn.laddr.port == sport or (conn.raddr and conn.raddr.port == dport):
            try:
                process = psutil.Process(conn.pid)
                return process.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                return "Unknown"
    return "Unknown"

def packet_callback(packet):
    """
    Обработка захваченных пакетов и их группировка по процессам
    """
    if stop_sniffing_flag.is_set():
        return

    if IP in packet:
        ip_layer = packet[IP]
        sport, dport = None, None
        proc_name = "Unknown"

        if TCP in packet or UDP in packet:
            sport = packet.sport
            dport = packet.dport
            proc_name = get_process_info(sport, dport)

        with update_lock:
            # Группировка пакетов по именам процессов
            if proc_name not in process_packets:
                process_packets[proc_name] = []
                # Insert new process node in Treeview
                proc_id = packets_tree.insert("", "end", text=proc_name, values=(proc_name,))
                process_packets[proc_name].append(packet)
                # Insert new packet under the process node
                insert_packet_to_tree(proc_id, packet, len(process_packets[proc_name]) - 1)
            else:
                process_packets[proc_name].append(packet)
                # Insert new packet under the existing process node
                proc_id = packets_tree.get_children()[list(process_packets.keys()).index(proc_name)]
                insert_packet_to_tree(proc_id, packet, len(process_packets[proc_name]) - 1)

def insert_packet_to_tree(parent, packet, packet_id):
    """
    Вставить пакет в дерево пакетов
    """
    packet_size = len(packet)
    if TCP in packet or UDP in packet:
        ip_layer = packet[IP]
        sport = packet.sport
        dport = packet.dport
        packet_summary = f"{ip_layer.src}:{sport} -> {ip_layer.dst}:{dport} ({packet_size} bytes)"
    else:
        ip_layer = packet[IP]
        packet_summary = f"{ip_layer.src} -> {ip_layer.dst} ({packet_size} bytes)"

    packets_tree.insert(parent, "end", iid=f"{parent}_{packet_id}", text=f"Packet {packet_id}", values=(packet_summary, packet_size))

def on_packet_select(event):
    """
    Отобразить детали выбранного пакета
    """
    selected_items = packets_tree.selection()
    if not selected_items:
        return

    selected_item = selected_items[0]
    parent_id, packet_id = selected_item.rsplit('_', 1)
    packet_id = int(packet_id)

    proc_name = packets_tree.item(parent_id, "values")[0]
    packets = process_packets[proc_name]
    packet = packets[packet_id]

    # Очищаем дерево
    for i in packet_details_tree.get_children():
        packet_details_tree.delete(i)

    # Вставить детали пакета
    insert_packet_details("", packet)

    raw_text.delete("1.0", tk.END)
    raw_text.insert(tk.END, hexdump(packet, dump=True))

def insert_packet_details(parent, packet):
    """
    Вставить детали пакета в дерево деталей
    """
    if isinstance(packet, Packet):
        layer = packet.__class__.__name__
        layer_id = packet_details_tree.insert(parent, "end", text=layer)

        for field_name, field_value in packet.fields.items():
            field_desc = packet.get_field(field_name).i2repr(packet, field_value)
            user_friendly_desc = field_descriptions.get(field_name, "No description available")
            packet_details_tree.insert(layer_id, "end", text=f"{field_name}: {field_value}", values=(user_friendly_desc,))

        # Рекурсивно вставлять данные полезной нагрузки
        if packet.payload:
            insert_packet_details(layer_id, packet.payload)

def start_sniffing_on_interface(interface):
    """
    Захват пакетов на определенном интерфейсе
    """
    try:
        stop_sniffing_flag.clear()
        sniff(iface=interface, prn=packet_callback, store=0)
    except Exception as e:
        output_text.insert(tk.END, f"[ERROR] Problem with interface {interface}: {str(e)}\n")
        output_text.see(tk.END)

def start_sniffing():
    """
    Захват пакетов на всех доступных интерфейсах
    """
    global sniff_threads
    interfaces = get_if_list()
    output_text.insert(tk.END, f"[INFO] Available interfaces: {interfaces}\n")

    for interface in interfaces:
        sniff_thread = threading.Thread(target=start_sniffing_on_interface, args=(interface,))
        sniff_thread.start()
        sniff_threads.append(sniff_thread)

def stop_sniffing():
    """
    Функция для остановки захвата пакетов
    """
    stop_sniffing_flag.set()
    output_text.insert(tk.END, "\n[INFO] Stopping sniffing...\n")

    for thread in sniff_threads:
        thread.join()
    sniff_threads.clear()

# Создание основного окна
root = tk.Tk()
root.title("Network Traffic Monitor")
root.geometry("1000x700")

# Основной фрейм с таблицей и панелью пакетов сбоку
main_frame = ttk.PanedWindow(root, orient=tk.HORIZONTAL)
main_frame.pack(fill=tk.BOTH, expand=1)

# Фрейм для таблицы пакетов (Packet Table Frame)
packet_table_frame = ttk.Labelframe(main_frame, text="Captured Packets")
main_frame.add(packet_table_frame, weight=1)

columns = ("Process", "Size")
packets_tree = ttk.Treeview(packet_table_frame, columns=columns, show="tree")
packets_tree.heading("#0", text="Process/Packet")
packets_tree.heading("Process", text="Summary")
packets_tree.heading("Size", text="Size")
packets_tree.column("#0", width=200)
packets_tree.column("Process", width=400)
packets_tree.column("Size", width=100, anchor=tk.E)
packets_tree.pack(fill=tk.BOTH, expand=1)

# Фрейм для панели детализации пакетов (Packet Details Panel)
details_panel_frame = ttk.Labelframe(main_frame, text="Packet Details Panel")
main_frame.add(details_panel_frame, weight=2)

details_panel = ttk.PanedWindow(details_panel_frame, orient=tk.VERTICAL)
details_panel.pack(fill=tk.BOTH, expand=1)

# Packet details frame
details_frame = ttk.Labelframe(details_panel, text="Packet Details")
details_frame.pack(fill=tk.BOTH, expand=1)
details_panel.add(details_frame, weight=1)

packet_details_tree = ttk.Treeview(details_frame, show="tree", columns=("Description",))
packet_details_tree.heading("#0", text="Field")
packet_details_tree.heading("Description", text="Description")
packet_details_tree.column("Description", stretch=True)
packet_details_tree.pack(fill=tk.BOTH, expand=1)

# Raw packet data frame
raw_frame = ttk.Labelframe(details_panel, text="Raw Packet Data")
raw_frame.pack(fill=tk.BOTH, expand=1)
details_panel.add(raw_frame, weight=1)

raw_text = scrolledtext.ScrolledText(raw_frame, height=10)
raw_text.pack(fill=tk.BOTH, expand=1)

packets_tree.bind("<<TreeviewSelect>>", on_packet_select)

# Output text area under Packet Table
output_frame = tk.Frame(root)
output_frame.pack(side=tk.BOTTOM, fill=tk.BOTH)

output_text = scrolledtext.ScrolledText(output_frame, height=5, state='normal', wrap=tk.WORD)
output_text.pack(fill=tk.BOTH, padx=10, pady=10)

# Start sniffing on startup
start_sniffing()

root.mainloop()

# Stop sniffing on exit
stop_sniffing_flag.set()