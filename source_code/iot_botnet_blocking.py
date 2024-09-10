import re
import json
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox
from PIL import Image, ImageTk  # type: ignore
import matplotlib.pyplot as plt # type: ignore
from collections import Counter

def parse_iptables_logs():
    # komutu çalıştırarak iptables loglarını oku
    command = "cat /var/log/kern.log | grep -a 'iptables:'"
    logs = subprocess.check_output(command, shell=True, text=True)

    # log satırlarını böl ve parsed_data listesi oluştur
    log_lines = logs.split("\n")
    parsed_data = []
    number = 1

    # her log satırı için
    for line in log_lines:
        if 'OUT=lo' not in line and 'IN=lo' not in line:
            data = {'number': number}
            # log satırındaki bilgileri düzenli ifadelerle yakala
            match = re.search(r'\[(.*?)\] iptables: IN=([^ ]+) .* SRC=([^ ]+) DST=([^ ]+) .* PROTO=([^ ]+) SPT=([^ ]+) DPT=([^ ]+)', line)
            if match:
                data['source_ip'] = match.group(3)
                data['destination_ip'] = match.group(4)
                data['protocol'] = match.group(5)
                data['source_port'] = match.group(6)
                data['destination_port'] = match.group(7)
                parsed_data.append(data)
                number += 1

    return parsed_data

def add_iptables_rule(chain, source, destination, protocol, action):
    try:
        # iptables kuralı eklemek için komut çalıştır
        command = f"sudo iptables -A {chain} -s {source} -d {destination} -p {protocol} -j {action}"
        subprocess.check_output(command, shell=True)
        return {"message": "Kural başarıyla eklendi."}
    except subprocess.CalledProcessError as e:
        return {"error": f"Komut '{e.cmd}' sıfırdan farklı çıkış durumu {e.returncode} döndürdü."}

def delete_iptables_rule(chain, rule_number):
    try:
        # iptables kuralını silmek için komut çalıştır
        command = f"sudo iptables -D {chain} {rule_number}"
        subprocess.check_output(command, shell=True)
        return {"message": "Kural başarıyla silindi."}
    except subprocess.CalledProcessError as e:
        return {"error": f"Komut '{e.cmd}' sıfırdan farklı çıkış durumu {e.returncode} döndürdü."}

def get_iptables_rules(chain):
    try:
        # belirli bir zincirdeki iptables kurallarını listelemek için komut çalıştır
        command = f"sudo iptables -L {chain} -n -v --line-numbers"
        output = subprocess.check_output(command, shell=True, text=True)
        lines = output.split('\n')
        rules = []

        # kuralları satır satır işle
        for line in lines[2:]:
            if line:
                parts = re.split(r'\s+', line)
                if len(parts) >= 10:
                    rule = {
                        "number": parts[0],
                        "source": parts[8],
                        "destination": parts[9],
                        "protocol": parts[4],
                        "target": parts[3]
                    }
                    rules.append(rule)
        return rules
    except subprocess.CalledProcessError as e:
        return []

class AnimatedButton(tk.Button):
    def __init__(self, master=None, **kwargs):
        super().__init__(master, **kwargs)
        self.default_bg = self["bg"]
        self.hover_bg = "#555"
        self.default_fg = self["fg"]
        self.hover_fg = "#fff"
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)

    def on_enter(self, event):
        # Fare butonun üzerine geldiğinde arka plan ve yazı rengini değiştir
        self.config(bg=self.hover_bg, fg=self.hover_fg)

    def on_leave(self, event):
        # Fare butondan ayrıldığında arka plan ve yazı rengini eski haline döndür
        self.config(bg=self.default_bg, fg=self.default_fg)

class LogViewerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("IOT BOTNET BLOCKING")
        self.root.geometry("1000x700")
        self.root.configure(bg='#2b2b2b')

        # Başlık
        self.header = tk.Frame(self.root, bg="#3b3b3b")
        self.header.pack(fill=tk.X)

        self.header_inner = tk.Frame(self.header, bg="#3b3b3b")
        self.header_inner.pack(pady=10)

        # Logo resmini yükle
        logo_image = Image.open("logo.png")
        logo_image = logo_image.resize((50, 50), Image.Resampling.LANCZOS)
        self.logo = ImageTk.PhotoImage(logo_image)
        self.logo_label = tk.Label(self.header_inner, image=self.logo, bg="#3b3b3b")
        self.logo_label.pack(side=tk.LEFT, padx=10)

        self.header_label = tk.Label(self.header_inner, text="IOT BOTNET BLOCKING", bg="#3b3b3b", fg="white", font=("Arial", 24, "bold"))
        self.header_label.pack(side=tk.LEFT)

        # Menü çerçevesi
        self.menu_frame = tk.Frame(self.root, bg="#444")
        self.menu_frame.pack(fill=tk.X, pady=10)

        # Menü çerçevesini ortala
        self.menu_inner_frame = tk.Frame(self.menu_frame, bg="#444")
        self.menu_inner_frame.pack(anchor=tk.CENTER)

        # Menü butonları ekle
        self.add_menu_button("Log Monitoring", self.load_logs)
        self.add_menu_button("Inbound Rules", self.show_input)
        self.add_menu_button("Outbound Rules", self.show_output)
        self.add_menu_button("Create New Rule", self.show_add_rule)
        self.add_menu_button("IP Distribution", self.show_ip_distribution)  # Yeni buton

        # İçerik
        self.content = tk.Frame(self.root, bg='#2b2b2b')
        self.content.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.table = None
        self.search_entry = None

    def add_menu_button(self, text, command):
        # Menü butonu oluştur ve menü çerçevesine ekle
        button = AnimatedButton(self.menu_inner_frame, text=text, bg="#444", fg="#ddd", relief=tk.FLAT, command=command, font=("Arial", 14), width=15)
        button.pack(side=tk.LEFT, padx=5)

    def show_message(self, message):
        # İçerikteki widgetları temizle ve mesaj göster
        for widget in self.content.winfo_children():
            widget.destroy()
        label = tk.Label(self.content, text=message, font=("Arial", 16), bg='#2b2b2b', fg='white')
        label.pack(pady=20)

    def load_logs(self):
        # Logları yükle ve göster
        logs = parse_iptables_logs()
        self.display_logs(logs)

    def display_logs(self, logs):
        # İçerikteki widgetları temizle ve logları tablo şeklinde göster
        for widget in self.content.winfo_children():
            widget.destroy()

        self.search_entry = tk.Entry(self.content, font=("Arial", 14), bg='#444', fg='white')
        self.search_entry.pack(pady=10)
        search_button = tk.Button(self.content, text="Search Logs", command=self.search_logs, bg="#444", fg="white", font=("Arial", 12))
        search_button.pack(pady=5)

        self.table_frame = tk.Frame(self.content)
        self.table_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("number", "source_ip", "destination_ip", "source_port", "destination_port", "protocol")
        self.table = ttk.Treeview(self.table_frame, columns=columns, show="headings", style="Custom.Treeview")
        self.table.heading("number", text="Rule Number")
        self.table.heading("source_ip", text="Source Address")
        self.table.heading("destination_ip", text="Destination Address")
        self.table.heading("source_port", text="Source Port")
        self.table.heading("destination_port", text="Destination Port")
        self.table.heading("protocol", text="Protocol")

        for col in columns:
            self.table.column(col, anchor=tk.CENTER)

        for i, log in enumerate(logs):
            tag = 'evenrow' if i % 2 == 0 else 'oddrow'
            self.table.insert("", tk.END, values=(log["number"], log["source_ip"], log["destination_ip"], log["source_port"], log["destination_port"], log["protocol"]), tags=(tag,))

        self.table.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        scrollbar = ttk.Scrollbar(self.table_frame, orient=tk.VERTICAL, command=self.table.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.table.configure(yscrollcommand=scrollbar.set)

        style = ttk.Style()
        style.configure("Custom.Treeview",
                        background="#2b2b2b",
                        foreground="white",
                        rowheight=25,
                        fieldbackground="#2b2b2b",
                        font=("Arial", 12))
        style.map("Custom.Treeview",
                  background=[('selected', '#555')])
        style.configure("Custom.Treeview.Heading",
                        background="#3b3b3b",
                        foreground="white",
                        font=("Arial", 12, "bold"),
                        borderwidth=1)
        style.map("Custom.Treeview.Heading",
                  background=[('active', '#555')],
                  foreground=[('active', 'white')])

        self.table.tag_configure('evenrow', background='#3b3b3b')
        self.table.tag_configure('oddrow', background='#2b2b2b')

    def search_logs(self):
        # Arama terimini al ve tablo satırlarını ara
        search_term = self.search_entry.get().lower()
        found = False
        for row in self.table.get_children():
            values = self.table.item(row)["values"]
            if any(search_term in str(value).lower() for value in values):
                self.table.item(row, tags="match")
                self.table.tag_configure("match", background="#666")
                if not found:
                    self.table.see(row)
                    found = True
            else:
                self.table.item(row, tags="nomatch")
                self.table.tag_configure("nomatch", background="#2b2b2b")

    def show_input(self):
        # INPUT zincirindeki kuralları al ve göster
        rules = get_iptables_rules("INPUT")
        self.display_rules(rules, "INPUT")

    def show_output(self):
        # OUTPUT zincirindeki kuralları al ve göster
        rules = get_iptables_rules("OUTPUT")
        self.display_rules(rules, "OUTPUT")

    def display_rules(self, rules, chain):
        # İçerikteki widgetları temizle ve kuralları tablo şeklinde göster
        for widget in self.content.winfo_children():
            widget.destroy()

        self.table_frame = tk.Frame(self.content)
        self.table_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("number", "source", "destination", "protocol", "target")
        self.table = ttk.Treeview(self.table_frame, columns=columns, show="headings", style="Custom.Treeview")
        self.table.heading("number", text="Rule Number")
        self.table.heading("source", text="Source Address")
        self.table.heading("destination", text="Destination Address")
        self.table.heading("protocol", text="Protocol")
        self.table.heading("target", text="Action")

        for col in columns:
            self.table.column(col, anchor=tk.CENTER)

        for i, rule in enumerate(rules):
            tag = 'evenrow' if i % 2 == 0 else 'oddrow'
            self.table.insert("", tk.END, values=(rule["number"], rule["source"], rule["destination"], rule["protocol"], rule["target"]), tags=(tag,))

        self.table.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        scrollbar = ttk.Scrollbar(self.table_frame, orient=tk.VERTICAL, command=self.table.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.table.configure(yscrollcommand=scrollbar.set)

        delete_button = tk.Button(self.content, text="Remove Selected Rule(s)", command=lambda: self.delete_selected_rules(chain), bg="#444", fg="white", font=("Arial", 12))
        delete_button.pack(pady=10)

        style = ttk.Style()
        style.configure("Custom.Treeview",
                        background="#2b2b2b",
                        foreground="white",
                        rowheight=25,
                        fieldbackground="#2b2b2b",
                        font=("Arial", 12))
        style.map("Custom.Treeview",
                  background=[('selected', '#555')])
        style.configure("Custom.Treeview.Heading",
                        background="#3b3b3b",
                        foreground="white",
                        font=("Arial", 12, "bold"),
                        borderwidth=1)
        style.map("Custom.Treeview.Heading",
                  background=[('active', '#555')],
                  foreground=[('active', 'white')])

        self.table.tag_configure('evenrow', background='#3b3b3b')
        self.table.tag_configure('oddrow', background='#2b2b2b')

    def delete_selected_rules(self, chain):
        # Seçili kuralları sil
        selected_items = self.table.selection()
        for item in selected_items:
            rule_number = self.table.item(item)["values"][0]
            result = delete_iptables_rule(chain, rule_number)
            if "error" in result:
                messagebox.showerror("Error", result["error"])
            else:
                self.table.delete(item)
                messagebox.showinfo("Success", result["message"])

    def show_add_rule(self):
        # İçerikteki widgetları temizle ve yeni kural ekleme formunu göster
        for widget in self.content.winfo_children():
            widget.destroy()

        form_frame = tk.Frame(self.content, bg='#2b2b2b')
        form_frame.pack(fill=tk.BOTH, expand=True, padx=100, pady=50)

        tk.Label(form_frame, text="INPUT/OUTPUT", bg='#2b2b2b', fg='white', font=("Arial", 12)).pack(pady=5)
        chain_var = tk.StringVar(value="INPUT")
        tk.OptionMenu(form_frame, chain_var, "INPUT", "OUTPUT").pack(pady=5)

        tk.Label(form_frame, text="Source IP", bg='#2b2b2b', fg='white', font=("Arial", 12)).pack(pady=5)
        source_entry = tk.Entry(form_frame, font=("Arial", 12), bg='#444', fg='white')
        source_entry.pack(pady=5)

        tk.Label(form_frame, text="Destination IP", bg='#2b2b2b', fg='white', font=("Arial", 12)).pack(pady=5)
        destination_entry = tk.Entry(form_frame, font=("Arial", 12), bg='#444', fg='white')
        destination_entry.pack(pady=5)

        tk.Label(form_frame, text="Protocol", bg='#2b2b2b', fg='white', font=("Arial", 12)).pack(pady=5)
        protocol_var = tk.StringVar(value="TCP")
        tk.OptionMenu(form_frame, protocol_var, "TCP", "UDP", "ICMP", "ALL").pack(pady=5)

        tk.Label(form_frame, text="Action", bg='#2b2b2b', fg='white', font=("Arial", 12)).pack(pady=5)
        action_var = tk.StringVar(value="ACCEPT")
        tk.OptionMenu(form_frame, action_var, "ACCEPT", "DROP").pack(pady=5)

        submit_button = tk.Button(form_frame, text="Add Rule", bg="#444", fg="white", font=("Arial", 12), command=lambda: self.submit_rule(chain_var.get(), source_entry.get(), destination_entry.get(), protocol_var.get(), action_var.get()))
        submit_button.pack(pady=20)

    def submit_rule(self, chain, source, destination, protocol, action):
        # Yeni kuralı ekle ve sonucu göster
        result = add_iptables_rule(chain, source, destination, protocol, action)
        if "error" in result:
            messagebox.showerror("Error", result["error"])
        else:
            messagebox.showinfo("Success", result["message"])

    def show_ip_distribution(self):
        # Logları yükle ve IP dağılımını göster
        logs = parse_iptables_logs()
        show_ip_distribution(logs)  # Yeni metodu çağır

def show_ip_distribution(logs):
    # Kaynak IP'leri say
    source_ips = [log['source_ip'] for log in logs]
    ip_counter = Counter(source_ips)
    
    # En çoktan en aza sıralama
    sorted_ip_counts = ip_counter.most_common()
    ip_labels = [item[0] for item in sorted_ip_counts]
    ip_counts = [item[1] for item in sorted_ip_counts]

    explode = [0.1 if count / sum(ip_counts) > 0.1 else 0 for count in ip_counts]

    plt.figure(figsize=(10, 6))
    wedges, texts = plt.pie(ip_counts, labels=None, startangle=140, explode=explode)
    percentages = [f'{count / sum(ip_counts) * 100:.1f}%' for count in ip_counts]
    legend_labels = [f'{label}: {percentage}' for label, percentage in zip(ip_labels, percentages)]
    
    plt.legend(wedges, legend_labels, title="Source IPs", loc="center left", bbox_to_anchor=(0.8, 0, 0.5, 1))
    plt.axis('equal')
    plt.title("Source IP Address Distribution")
    plt.show()

class LoginApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Kullanıcı Giriş Paneli")
        self.root.geometry("400x500")
        self.root.configure(bg='#0f0c29')

        self.canvas = tk.Canvas(self.root, width=400, height=500)
        self.canvas.pack(fill="both", expand=True)
        self.canvas.create_rectangle(0, 0, 400, 500, fill="#302b63")
        self.canvas.create_rectangle(0, 0, 400, 250, fill="#24243e")

        self.logo_image = Image.open("logo.png")
        self.logo_image = self.logo_image.resize((100, 100), Image.Resampling.LANCZOS)
        self.logo = ImageTk.PhotoImage(self.logo_image)
        self.logo_label = tk.Label(self.root, image=self.logo, bg="#24243e")
        self.logo_label.place(relx=0.5, rely=0.2, anchor=tk.CENTER)

        self.form_frame = tk.Frame(self.root, bg="#333333", padx=20, pady=20, bd=0, relief=tk.FLAT)
        self.form_frame.place(relx=0.5, rely=0.6, anchor=tk.CENTER)
        self.form_frame.config(bg='#333333', highlightthickness=1, highlightbackground="#444444")
        self.form_frame.configure(highlightthickness=0, borderwidth=0)

        self.title = tk.Label(self.form_frame, text="IOT Botnet Blocking System", font=("Segoe UI", 16), fg="#E2E2E2", bg="#333333")
        self.title.pack(pady=5)

        self.username_entry = tk.Entry(self.form_frame, font=("Segoe UI", 12), width=25, bg="#444444", fg="#eee", bd=0, relief=tk.FLAT)
        self.username_entry.insert(0, "Username")
        self.username_entry.bind("<FocusIn>", self.clear_username)
        self.username_entry.pack(pady=5)

        self.password_entry = tk.Entry(self.form_frame, font=("Segoe UI", 12), width=25, bg="#444444", fg="#eee", bd=0, relief=tk.FLAT, show="*")
        self.password_entry.insert(0, "Password")
        self.password_entry.bind("<FocusIn>", self.clear_password)
        self.password_entry.pack(pady=5)

        self.login_button = tk.Button(self.form_frame, text="Login", font=("Segoe UI", 12), bg="#5A5A5A", fg="white", bd=0, relief=tk.FLAT, command=self.check_login)
        self.login_button.pack(pady=10)

    def clear_username(self, event):
        # Kullanıcı adı alanı tıklanınca temizle
        if self.username_entry.get() == "Username":
            self.username_entry.delete(0, tk.END)

    def clear_password(self, event):
        # Şifre alanı tıklanınca temizle ve şifre karakterlerini göster
        if self.password_entry.get() == "Password":
            self.password_entry.delete(0, tk.END)
            self.password_entry.config(show="*")

    def check_login(self):
        # Kullanıcı adı ve şifre kontrolü yap
        username = self.username_entry.get()
        password = self.password_entry.get()
        if username == "admin" and password == "admin":
            messagebox.showinfo("Login", "Login successful!")
            self.open_log_viewer()
        else:
            messagebox.showerror("Login", "Incorrect username or password!")

    def open_log_viewer(self):
        # Log görüntüleyiciyi aç
        self.root.destroy()
        root = tk.Tk()
        log_viewer_app = LogViewerApp(root)
        log_viewer_app.load_logs()
        root.mainloop()

if __name__ == "__main__":
    root = tk.Tk()
    login_app = LoginApp(root)
    root.mainloop()
