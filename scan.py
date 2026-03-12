import sys
import ctypes
import os
import subprocess
import threading
import time
import json
import tkinter as tk
from tkinter import messagebox, filedialog
import re

# --- SECCIÓN 1: PREPARACIÓN DEL ENTORNO ---

def install_dependencies():
    """
    Esta función revisa si tienes instaladas las librerías necesarias.
    Si falta alguna (como pandas para Excel o fpdf para PDF), la instala automáticamente.
    """
    required = ["pandas", "openpyxl", "fpdf"]
    for lib in required:
        try:
            # Intentamos importar la librería
            if lib == "fpdf":
                __import__("fpdf")
            else:
                __import__(lib)
        except ImportError:
            # Si no existe, usamos pip (el instalador de Python) para descargarla
            print(f"[*] Instalando dependencia faltante: {lib}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", lib])

# Ejecutamos la instalación de dependencias al abrir el programa
install_dependencies()

import pandas as pd
from fpdf import FPDF

# --- SECCIÓN 2: PERMISOS DE ADMINISTRADOR ---

def run_as_admin():
    """
    Nmap requiere permisos de administrador para realizar ciertos escaneos profundos.
    Esta función fuerza al programa a pedir esos permisos en Windows.
    """
    try:
        if ctypes.windll.shell32.IsUserAnAdmin(): 
            return True # Si ya somos admin, todo OK
        # Si no, pedimos a Windows que relance el programa como administrador
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{sys.argv[0]}"', None, 1)
        return False
    except: 
        return False

if __name__ == "__main__":
    # Si el usuario dice que "No" a los permisos, el programa se cierra
    if not run_as_admin(): sys.exit(0)

    # --- SECCIÓN 3: ESTÉTICA Y DISEÑO (THEME) ---

    class Theme:
        """ Definición de los colores 'Cyberpunk' de la interfaz """
        BG_DARK = "#0A0A0A"      # Fondo principal
        BG_PANEL = "#141414"     # Fondo de los cuadros
        FG_LIGHT = "#E0E0E0"     # Color de texto
        FG_DIM = "#666666"       # Texto apagado
        ACCENT = "#F700FF"       # Color rosa brillante
        ACCENT_HOVER = "#EE33FF" # Color rosa al pasar el ratón
        DANGER = "#D32F2F"       # Rojo para errores o stop
        BORDER = "#1E1E1E"       # Color de los bordes

    class RoundedButton(tk.Canvas):
        """ 
        Crea botones con bordes redondeados. 
        En Tkinter estándar los botones son cuadrados, así que los dibujamos manualmente.
        """
        def __init__(self, parent, text, command, color, hover_color, width=120, height=35):
            super().__init__(parent, width=width, height=height, bg=parent['bg'], highlightthickness=0)
            self.command, self.base_color, self.hover_color = command, color, hover_color
            self.rect = self._draw_rounded_rect(0, 0, width, height, 15, fill=color)
            self.text_id = self.create_text(width/2, height/2, text=text, fill="white", font=("Segoe UI", 9, "bold"))
            
            # Eventos: cambiar de color al pasar el ratón
            self.bind("<Enter>", lambda _: self.itemconfig(self.rect, fill=self.hover_color))
            self.bind("<Leave>", lambda _: self.itemconfig(self.rect, fill=self.base_color))
            self.bind("<Button-1>", lambda _: self._execute())

        def _draw_rounded_rect(self, x, y, w, h, r, **kwargs):
            points = [x+r, y, x+w-r, y, x+w, y, x+w, y+r, x+w, y+h-r, x+w, y+h, x+w-r, y+h, x+r, y+h, x, y+h, x, y+h-r, x, y+r, x, y]
            return self.create_polygon(points, **kwargs, smooth=True)

        def _execute(self):
            if str(self.cget("state")) != "disabled" and self.command: self.command()

        def set_state(self, state):
            """ Activa o desactiva el botón visualmente """
            color = Theme.BORDER if state == "disabled" else self.base_color
            self.itemconfig(self.rect, fill=color); self.config(state=state)

    # --- SECCIÓN 4: LÓGICA PRINCIPAL DEL ESCÁNER ---

    class VulneraViewScanner:
        def __init__(self, root):
            self.root = root
            self.root.title("Port Auditer by Jacsaw")
            self.root.geometry("650x950")
            self.root.configure(bg=Theme.BG_DARK)
            
            self.running_proc = None # Aquí guardaremos el proceso de Nmap cuando esté corriendo
            self.scan_results = []   # Lista donde guardaremos los puertos abiertos encontrados
            self.total_ports_to_scan = 0
            
            # Configuración de los modos de escaneo de Nmap
            self.scan_modes = {
                "Fast Audit": {"cmd": "-F -sV --version-light", "desc": "Escaneo veloz de puertos comunes."},
                "Standard Audit": {"cmd": "-sV", "desc": "Equilibrio entre velocidad y detalle."},
                "Aggressive Audit": {"cmd": "-A", "desc": "Escaneo profundo: SO y scripts."},
                "Vuln Scan": {"cmd": "-sV --script vuln", "desc": "Busca vulnerabilidades conocidas."}
            }
            self._setup_gui()

        def _setup_gui(self):
            """ Construye todos los elementos visuales de la ventana """
            header = tk.Frame(self.root, bg=Theme.BG_DARK, pady=20)
            header.pack(fill=tk.X)
            tk.Label(header, text="PORT AUDITER", font=("Consolas", 30, "bold"), bg=Theme.BG_DARK, fg=Theme.ACCENT).pack()
            tk.Label(header, text="by Jacsaw", font=("Segoe UI", 10), bg=Theme.BG_DARK, fg=Theme.FG_DIM).pack()
            
            panel = tk.Frame(self.root, bg=Theme.BG_PANEL, padx=30, pady=20, highlightthickness=1, highlightbackground=Theme.BORDER)
            panel.pack(fill=tk.X, padx=40, pady=5)

            # Entradas de texto para IP y Puertos
            self.entry_ip = self._field(panel, "TARGET DESTINATION (IP)", "127.0.0.1", Theme.ACCENT)
            self.entry_ports = self._field(panel, "PORT RANGE (Vacio para 1-65535)", "", Theme.FG_LIGHT)

            # Selector de intensidad (T1 a T5 de Nmap)
            tk.Label(panel, text="SCAN POWER (CPU INTENSITY)", font=("Segoe UI", 8, "bold"), bg=Theme.BG_PANEL, fg=Theme.FG_DIM).pack(anchor="w")
            self.power_lvl = tk.Scale(panel, from_=1, to=5, orient=tk.HORIZONTAL, bg=Theme.BG_PANEL, fg=Theme.ACCENT, highlightthickness=0, troughcolor=Theme.BG_DARK)
            self.power_lvl.set(4); self.power_lvl.pack(fill=tk.X, pady=(0, 10))

            # Selector de modo de auditoría
            tk.Label(panel, text="AUDIT MODE", font=("Segoe UI", 8, "bold"), bg=Theme.BG_PANEL, fg=Theme.FG_DIM).pack(anchor="w")
            self.mode_var = tk.StringVar(value="Standard Audit")
            self.mode_var.trace("w", self._update_description)
            mode_menu = tk.OptionMenu(panel, self.mode_var, *self.scan_modes.keys())
            mode_menu.config(bg=Theme.BG_DARK, fg=Theme.FG_LIGHT, bd=0, highlightthickness=1, highlightbackground=Theme.BORDER)
            mode_menu.pack(fill=tk.X, pady=(5, 5))

            self.desc_label = tk.Label(panel, text=self.scan_modes[self.mode_var.get()]["desc"], font=("Segoe UI italic", 8), bg=Theme.BG_PANEL, fg=Theme.ACCENT, wraplength=500)
            self.desc_label.pack(pady=(0, 10))

            # Barra de progreso visual
            prog_f = tk.Frame(panel, bg=Theme.BG_PANEL)
            prog_f.pack(fill=tk.X)
            tk.Label(prog_f, text="PROGRESS", font=("Segoe UI", 7, "bold"), bg=Theme.BG_PANEL, fg=Theme.FG_DIM).pack(side=tk.LEFT)
            self.lbl_count = tk.Label(prog_f, text="Waiting...", font=("Consolas", 7), bg=Theme.BG_PANEL, fg=Theme.ACCENT)
            self.lbl_count.pack(side=tk.RIGHT)

            self.prog_canvas = tk.Canvas(panel, height=6, bg=Theme.BG_DARK, highlightthickness=0)
            self.prog_canvas.pack(fill=tk.X, pady=(2, 10))
            self.prog_bar = self.prog_canvas.create_rectangle(0, 0, 0, 6, fill=Theme.ACCENT, width=0)

            # Selector de formato de archivo
            tk.Label(panel, text="EXPORT FORMAT", font=("Segoe UI", 8, "bold"), bg=Theme.BG_PANEL, fg=Theme.FG_DIM).pack(anchor="w")
            self.export_var = tk.StringVar(value="Excel (.xlsx)")
            tk.OptionMenu(panel, self.export_var, "Excel (.xlsx)", "JSON (.json)", "PDF (.pdf)", "Plain Text (.txt)").pack(fill=tk.X, pady=(5, 10))

            # Botones de acción
            btn_frame = tk.Frame(self.root, bg=Theme.BG_DARK, pady=15)
            btn_frame.pack(fill=tk.X, padx=40)
            self.btn_start = RoundedButton(btn_frame, "START SCAN", self.start_audit, Theme.ACCENT, Theme.ACCENT_HOVER)
            self.btn_start.pack(side=tk.LEFT, padx=(0, 10))
            self.btn_stop = RoundedButton(btn_frame, "STOP", self.stop_audit, "#222222", Theme.DANGER)
            self.btn_stop.pack(side=tk.LEFT, padx=(0, 10)); self.btn_stop.set_state("disabled")
            
            # BOTÓN EXIT REINTEGRADO AQUÍ
            self.btn_exit = RoundedButton(btn_frame, "EXIT", self.root.destroy, "#1A1A1A", Theme.DANGER)
            self.btn_exit.pack(side=tk.RIGHT)
            
            # Cuadro de Log (consola interna)
            self.txt_log = tk.Text(self.root, bg=Theme.BG_PANEL, fg=Theme.FG_LIGHT, font=("Consolas", 9), bd=0, padx=15, pady=15, state="disabled")
            self.txt_log.pack(fill=tk.BOTH, expand=True, padx=40, pady=20)

        def _field(self, p, t, d, c):
            """ Ayudante para crear campos de texto rápidamente """
            tk.Label(p, text=t, font=("Segoe UI", 8, "bold"), bg=Theme.BG_PANEL, fg=Theme.FG_DIM).pack(anchor="w")
            e = tk.Entry(p, font=("Consolas", 11), bg=Theme.BG_DARK, fg=c, bd=0, highlightthickness=1, highlightbackground=Theme.BORDER, insertbackground=Theme.ACCENT)
            e.pack(fill=tk.X, pady=(5, 10), ipady=5); e.insert(0, d); return e

        def _update_description(self, *args):
            """ Cambia el texto descriptivo según el modo seleccionado """
            self.desc_label.config(text=self.scan_modes[self.mode_var.get()]["desc"])

        def write_log(self, msg):
            """ Escribe mensajes en la consola visual del programa """
            self.txt_log.config(state="normal")
            self.txt_log.insert(tk.END, msg + "\n")
            self.txt_log.config(state="disabled")
            self.txt_log.see(tk.END) # Auto-scroll hacia abajo

        def start_audit(self):
            """ Prepara e inicia el escaneo """
            target = self.entry_ip.get().strip()
            ports_str = self.entry_ports.get().strip() or "1-65535"
            power = self.power_lvl.get()
            
            if not target: return
            
            # Cálculo estimado de puertos para la barra de progreso
            try:
                if "-" in ports_str:
                    s, e = map(int, ports_str.split("-")); self.total_ports_to_scan = (e - s) + 1
                else: self.total_ports_to_scan = len(ports_str.split(","))
            except: self.total_ports_to_scan = 1000

            self.btn_start.set_state("disabled")
            self.btn_stop.set_state("normal")
            self.txt_log.config(state="normal"); self.txt_log.delete(1.0, tk.END); self.txt_log.config(state="disabled")
            self.scan_results = []
            
            self.write_log(f"[*] INICIANDO AUDITORÍA EN: {target}...")
            
            # Comando de Nmap optimizado: Solo puertos abiertos (--open)
            cmd = ["nmap", f"-T{power}", "-v", "--open", self.scan_modes[self.mode_var.get()]["cmd"], "-p", ports_str, target, "--stats-every", "1s"]
            
            # Lanzamos el escaneo en un "hilo" separado para que la ventana no se congele
            threading.Thread(target=self._execute_engine, args=(cmd,), daemon=True).start()

        def _execute_engine(self, cmd):
            """ Motor que ejecuta Nmap y lee su salida en tiempo real """
            try:
                # Ejecuta el comando nmap.exe
                self.running_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, shell=True)
                
                capture_table = False
                for line in iter(self.running_proc.stdout.readline, ""):
                    # Si Nmap nos da una estadística de progreso, actualizamos la barra
                    if "Stats:" in line or "About" in line:
                        m = re.search(r"(\d+\.\d+)%", line)
                        if m:
                            p = float(m.group(1))
                            c = int((p/100) * self.total_ports_to_scan)
                            self.root.after(0, lambda v=p, curr=c: self._update_ui_prog(v, curr))

                    # Detectamos el inicio de la tabla de resultados
                    if "PORT" in line and "STATE" in line:
                        capture_table = True; continue
                    
                    if capture_table:
                        # Si la línea está vacía o dice "Nmap done", la tabla terminó
                        if not line.strip() or "Nmap done" in line:
                            if not line.strip() and capture_table: continue
                            capture_table = False
                        else:
                            # Cortamos la línea en trozos (Puerto, Estado, Servicio)
                            parts = re.split(r'\s+', line.strip())
                            if len(parts) >= 3 and parts[0][0].isdigit():
                                port_info, state, service = parts[0], parts[1], parts[2]
                                # Solo guardamos si es "open"
                                if "open" in state.lower():
                                    self.scan_results.append({"Host": self.entry_ip.get(), "Port": port_info, "State": state.upper(), "Service": service})
                                    self.write_log(f"[+] ABIERTO: {port_info} ({service})")

                self.running_proc.wait()
            except Exception as e: self.write_log(f"[ERROR] {e}")
            finally: self.root.after(0, self._finalize)

        def _update_ui_prog(self, p, curr):
            """ Actualiza la barra rosa de la interfaz """
            w = self.prog_canvas.winfo_width()
            self.prog_canvas.coords(self.prog_bar, 0, 0, int(w*(p/100)), 6)
            self.lbl_count.config(text=f"{p}% completado")

        def stop_audit(self):
            """ Detiene el proceso de Nmap inmediatamente """
            if self.running_proc: 
                self.running_proc.terminate()
                self.write_log("[!] ESCANEO DETENIDO POR EL USUARIO.")

        def _finalize(self):
            """ Se ejecuta al terminar el escaneo """
            self.btn_start.set_state("normal")
            self.btn_stop.set_state("disabled")
            self._update_ui_prog(100, self.total_ports_to_scan)
            
            if self.scan_results:
                if messagebox.askyesno("Finalizado", f"Se encontraron {len(self.scan_results)} puertos abiertos. ¿Exportar reporte?"):
                    self._export_data()
            else:
                messagebox.showinfo("Finalizado", "No se detectaron puertos abiertos en este rango.")

        def _export_data(self):
            """ Guarda los resultados en el formato elegido y pregunta si abrirlo """
            fmt = self.export_var.get()
            ext, ftypes = (".xlsx", [("Excel Files", "*.xlsx")]) if "Excel" in fmt else \
                          (".json", [("JSON Files", "*.json")]) if "JSON" in fmt else \
                          (".pdf", [("PDF Files", "*.pdf")]) if "PDF" in fmt else \
                          (".txt", [("Text Files", "*.txt")])

            path = filedialog.asksaveasfilename(initialfile="Audit_Report", defaultextension=ext, filetypes=ftypes)
            
            if path:
                try:
                    df = pd.DataFrame(self.scan_results)
                    if ext == ".xlsx": df.to_excel(path, index=False)
                    elif ext == ".json": df.to_json(path, orient="records", indent=4)
                    elif ext == ".pdf":
                        pdf = FPDF(); pdf.add_page(); pdf.set_font("Arial", 'B', 14)
                        pdf.cell(190, 10, "AUDIT REPORT", 1, 1, 'C'); pdf.ln(10)
                        pdf.set_font("Arial", 'B', 10); pdf.cell(60, 8, "Port", 1); pdf.cell(60, 8, "State", 1); pdf.cell(70, 8, "Service", 1); pdf.ln()
                        pdf.set_font("Arial", '', 9)
                        for r in self.scan_results:
                            pdf.cell(60, 7, str(r['Port']), 1); pdf.cell(60, 7, str(r['State']), 1); pdf.cell(70, 7, str(r['Service']), 1); pdf.ln()
                        pdf.output(path)
                    else:
                        df.to_csv(path, sep="|", index=False)
                    
                    if messagebox.askyesno("Éxito", "Reporte guardado. ¿Deseas abrirlo ahora?"):
                        os.startfile(path) # Abre el archivo con el programa predeterminado de Windows
                except Exception as e: 
                    messagebox.showerror("Error al guardar", str(e))

    # --- INICIO DE LA APLICACIÓN ---
    root = tk.Tk()
    app = VulneraViewScanner(root)
    root.mainloop()