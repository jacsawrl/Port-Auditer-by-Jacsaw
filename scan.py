import tkinter as tk # Librería base para la interfaz gráfica (GUI)
from tkinter import messagebox # Módulo para ventanas emergentes de alerta/confirmación
import socket # Permite la comunicación de red a bajo nivel (escaneo de puertos)
import threading # Permite ejecutar el escaneo en segundo plano sin congelar la ventana
from concurrent.futures import ThreadPoolExecutor # Administra múltiples hilos de forma eficiente (Pool)
import time # Para obtener marcas de tiempo y fechas para el reporte
import os # Para verificar rutas y existencia de archivos en el sistema
import re # Expresiones regulares para limpiar nombres de archivos de caracteres prohibidos

# --- CAPA DE CONFIGURACIÓN TÉCNICA ---
# Centraliza los parámetros del motor para facilitar el mantenimiento futuro.
class Config:
    MAX_WORKERS = 800          # Máximo de hilos en paralelo. A mayor número, más velocidad pero más carga de CPU.
    SOCKET_TIMEOUT = 0.5       # Segundos que el programa espera a que un puerto responda.
    PORT_MIN = 1               # Puerto inicial según el estándar TCP.
    PORT_MAX = 65535           # Puerto final (límite máximo de un ordenador).
    DEFAULT_FILENAME = "audit_report" # Nombre que aparecerá por defecto en la caja de texto.

# --- CAPA DE ESTILO ---
# Define la identidad visual del programa (Colores estilo Cyberpunk/Dark Mode).
class Theme:
    BG_DARK = "#0A0A0A"        # Negro puro para el fondo principal.
    BG_PANEL = "#141414"       # Gris muy oscuro para paneles y cajas de entrada.
    FG_LIGHT = "#E0E0E0"       # Color del texto principal.
    FG_DIM = "#666666"         # Color para textos secundarios o etiquetas.
    ACCENT = "#F700FF"         # Magenta neón (color principal de acción).
    ACCENT_HOVER = "#EE33FF"   # Tono de magenta para cuando el ratón pasa por encima.
    DANGER = "#D32F2F"         # Rojo para botones de detener o salir.
    BORDER = "#1E1E1E"         # Color de los bordes sutiles de los paneles.

# --- COMPONENTE: BOTÓN REDONDEADO PERSONALIZADO ---
# Crea un botón visualmente moderno usando el lienzo (Canvas) de Tkinter.
class RoundedButton(tk.Canvas):
    def __init__(self, parent, text, command, color, hover_color, width=120, height=35):
        super().__init__(parent, width=width, height=height, bg=parent['bg'], highlightthickness=0)
        self.command = command
        self.base_color = color
        self.hover_color = hover_color
        self.radius = 15
        
        # Dibuja la forma redondeada inicial.
        self.rect = self._draw_rounded_rect(0, 0, width, height, self.radius, fill=color)
        # Añade el texto centrado sobre la forma.
        self.text_id = self.create_text(width/2, height/2, text=text, fill="white", font=("Segoe UI", 9, "bold"))
        
        # Vincula eventos del ratón para efectos visuales (Hover) y ejecución (Click).
        self.bind("<Enter>", lambda _: self._update_color(self.hover_color))
        self.bind("<Leave>", lambda _: self._update_color(self.base_color))
        self.bind("<Button-1>", lambda _: self._execute())

    def _draw_rounded_rect(self, x, y, w, h, r, **kwargs):
        # Algoritmo de dibujo de polígono con puntos suavizados para crear las esquinas curvas.
        points = [x+r, y, x+r, y, x+w-r, y, x+w-r, y, x+w, y, x+w, y+r, x+w, y+r, x+w, y+h-r, x+w, y+h-r, x+w, y+h, x+w-r, y+h, x+w-r, y+h, x+r, y+h, x+r, y+h, x, y+h, x, y+h-r, x, y+h-r, x, y+r, x, y+r, x, y]
        return self.create_polygon(points, **kwargs, smooth=True)

    def _update_color(self, color):
        # Cambia el color del botón solo si no está en estado 'desactivado'.
        if str(self.cget("state")) != "disabled":
            self.itemconfig(self.rect, fill=color)

    def _execute(self):
        # Ejecuta la función asignada al botón al hacer click.
        if self.command and str(self.cget("state")) != "disabled":
            self.command()

    def set_state(self, state):
        # Cambia el estado visual (activo/gris) y funcional del botón.
        if state == "disabled":
            self.config(state="disabled")
            self.itemconfig(self.rect, fill=Theme.BORDER)
            self.itemconfig(self.text_id, fill=Theme.FG_DIM)
        else:
            self.config(state="normal")
            self.itemconfig(self.rect, fill=self.base_color)
            self.itemconfig(self.text_id, fill="white")

# --- MOTOR PRINCIPAL DEL AUDITOR ---
# Clase que gestiona toda la lógica del escáner y la ventana principal.
class ModernPortScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Port Auditor - v1.0 by Jacsaw")
        self.root.geometry("600x850") # Establece el tamaño de la ventana (Ancho x Alto).
        self.root.configure(bg=Theme.BG_DARK) # Color de fondo de la ventana principal.
        
        # Variables de control de estado interno.
        self.running_flag = False   # Indica si el escaneo está en marcha o se debe detener.
        self.processed_count = 0    # Contador de cuántos puertos se han analizado ya.
        self.open_ports = []        # Lista dinámica para guardar solo los puertos abiertos encontrados.
        self.scanned_range = []     # Copia del rango solicitado para generar el reporte final.
        
        self._setup_gui() # Llama a la construcción de la interfaz.

    def _setup_gui(self):
        """Construye todos los elementos visuales de la interfaz."""
        # Cabecera con el título del programa.
        header = tk.Frame(self.root, bg=Theme.BG_DARK, pady=20)
        header.pack(fill=tk.X)
        tk.Label(header, text="PORT AUDITOR", font=("Consolas", 28, "bold"), bg=Theme.BG_DARK, fg=Theme.ACCENT).pack()
        
        # Contenedor principal de configuración.
        panel = tk.Frame(self.root, bg=Theme.BG_PANEL, padx=30, pady=20, highlightthickness=1, highlightbackground=Theme.BORDER)
        panel.pack(fill=tk.X, padx=40, pady=5)

        # Campo para la dirección IP o Dominio.
        self._create_label(panel, "TARGET DESTINATION (IP/DOMAIN)")
        self.entry_ip = self._create_entry(panel, "127.0.0.1", Theme.ACCENT)

        # Campo para el nombre del archivo de reporte.
        self._create_label(panel, "REPORT FILENAME")
        self.entry_filename = self._create_entry(panel, Config.DEFAULT_FILENAME, Theme.FG_LIGHT)

        # Opción para optimizar el reporte (Solo abiertos vs Todos).
        self.var_only_open = tk.BooleanVar(value=True)
        tk.Checkbutton(panel, text="Export only OPEN ports (Recommended)", 
                       variable=self.var_only_open, bg=Theme.BG_PANEL, fg=Theme.FG_LIGHT, 
                       selectcolor=Theme.BG_DARK, activebackground=Theme.BG_PANEL,
                       font=("Segoe UI", 8)).pack(anchor="w", pady=(5, 0))

        # Checkbox para activar el modo manual de puertos.
        self.var_manual = tk.BooleanVar()
        tk.Checkbutton(panel, text=f"Manual Port Mode (Custom range/list)(80,443/1-1024)", 
                       variable=self.var_manual, command=self._toggle_ports, 
                       bg=Theme.BG_PANEL, fg=Theme.FG_LIGHT, selectcolor=Theme.BG_DARK,
                       activebackground=Theme.BG_PANEL, font=("Segoe UI", 9)).pack(anchor="w", pady=(10, 0))
        
        # Campo de texto para los puertos manuales (Empieza desactivado).
        self.entry_ports = self._create_entry(panel, f"{Config.PORT_MIN}-{Config.PORT_MAX}", Theme.FG_DIM)
        self.entry_ports.config(state="disabled")

        # Fila de botones de acción (Iniciar, Detener, Salir).
        btn_frame = tk.Frame(self.root, bg=Theme.BG_DARK, pady=10)
        btn_frame.pack(fill=tk.X, padx=40)
        
        self.btn_start = RoundedButton(btn_frame, "START SCAN", self.start_audit, Theme.ACCENT, Theme.ACCENT_HOVER)
        self.btn_start.pack(side=tk.LEFT, padx=(0, 10))
        
        self.btn_stop = RoundedButton(btn_frame, "STOP", self.stop_audit, "#222222", Theme.DANGER)
        self.btn_stop.pack(side=tk.LEFT); self.btn_stop.set_state("disabled")
        
        RoundedButton(btn_frame, "EXIT", self.root.destroy, "#222222", Theme.DANGER).pack(side=tk.RIGHT)

        # Etiquetas de estado y barra de progreso visual.
        self.status_label = tk.Label(self.root, text="SYSTEM READY", font=("Consolas", 9), bg=Theme.BG_DARK, fg=Theme.FG_DIM)
        self.status_label.pack(pady=(10, 0))
        
        progress_bg = tk.Frame(self.root, bg=Theme.BG_PANEL, height=2)
        progress_bg.pack(fill=tk.X, padx=40, pady=15)
        self.prog_bar = tk.Frame(progress_bg, bg=Theme.ACCENT, height=2, width=0)
        self.prog_bar.place(x=0, y=0)

        # Área de log para mostrar los resultados en tiempo real mientras ocurre el escaneo.
        log_frame = tk.Frame(self.root, bg=Theme.BG_DARK, padx=40, pady=5)
        log_frame.pack(fill=tk.BOTH, expand=True)
        self.txt_log = tk.Text(log_frame, bg=Theme.BG_PANEL, fg=Theme.FG_LIGHT, font=("Consolas", 9), bd=0, padx=15, pady=15, state="disabled")
        self.txt_log.pack(fill=tk.BOTH, expand=True)

    def _create_label(self, parent, text):
        """Helper para crear etiquetas con el estilo del panel."""
        tk.Label(parent, text=text, font=("Segoe UI", 8, "bold"), bg=Theme.BG_PANEL, fg=Theme.FG_DIM).pack(anchor="w")

    def _create_entry(self, parent, default_val, fg_color):
        """Helper para crear campos de entrada con estilo uniforme."""
        e = tk.Entry(parent, font=("Consolas", 11), bg=Theme.BG_DARK, fg=fg_color, bd=0, 
                     insertbackground=Theme.ACCENT, highlightthickness=1, highlightbackground=Theme.BORDER, highlightcolor=Theme.ACCENT)
        e.pack(fill=tk.X, pady=(5, 10), ipady=5)
        e.insert(0, default_val)
        return e

    def _toggle_ports(self):
        """Activa o desactiva la caja de texto de puertos según el checkbox manual."""
        state = "normal" if self.var_manual.get() else "disabled"
        self.entry_ports.config(state=state, fg=Theme.FG_LIGHT if state=="normal" else Theme.FG_DIM)

    def write_log(self, message):
        """Añade una línea de texto al área de log de forma segura."""
        self.txt_log.config(state="normal")
        self.txt_log.insert(tk.END, f"{message}\n")
        self.txt_log.config(state="disabled")
        self.txt_log.see(tk.END) # Auto-scroll hacia abajo.

    def update_ui_progress(self):
        """Actualiza la barra de progreso y el texto de estado."""
        self.processed_count += 1
        if self.processed_count % 100 == 0 or self.processed_count == self.total_count:
            self.status_label.config(text=f"AUDITING: {self.processed_count} / {self.total_count}")
            new_width = (self.processed_count / self.total_count) * 520
            self.prog_bar.config(width=new_width)

    def port_scanner_engine(self, host, port):
        """Función núcleo que intenta conectar a un puerto IP."""
        if not self.running_flag: return
        try:
            # Crea un objeto socket para comunicación TCP.
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(Config.SOCKET_TIMEOUT)
                # connect_ex devuelve 0 si la conexión fue exitosa (puerto abierto).
                if s.connect_ex((host, port)) == 0:
                    self.open_ports.append(port)
                    # Actualiza la interfaz desde el hilo principal usando .after()
                    self.root.after(0, lambda: self.write_log(f"[+] FOUND OPEN: {port}"))
        except: pass
        finally:
            self.root.after(0, self.update_ui_progress)

    def start_audit(self):
        """Valida entradas y lanza el hilo de escaneo."""
        target = self.entry_ip.get().strip()
        if not target: return

        # Lógica para determinar qué puertos escanear.
        try:
            if self.var_manual.get():
                raw = self.entry_ports.get().replace(" ", "")
                if '-' in raw: # Rango (ej. 1-100)
                    start_p, end_p = map(int, raw.split('-'))
                    start_p = max(Config.PORT_MIN, start_p)
                    end_p = min(Config.PORT_MAX, end_p)
                    ports = list(range(start_p, end_p + 1))
                else: # Lista (ej. 80,443)
                    ports = [int(p) for p in raw.split(',') if Config.PORT_MIN <= int(p) <= Config.PORT_MAX]
            else:
                # Escaneo completo por defecto.
                ports = list(range(Config.PORT_MIN, Config.PORT_MAX + 1))
        except Exception:
            messagebox.showerror("Port Error", "Use format '80,443' or '1-1024'."); return

        # Inicialización de variables para la nueva sesión.
        self.scanned_range = ports
        self.running_flag, self.processed_count, self.total_count, self.open_ports = True, 0, len(ports), []
        
        # Bloquea el botón de inicio y activa el de parada.
        self.btn_start.set_state("disabled")
        self.btn_stop.set_state("normal")
        self.txt_log.config(state="normal"); self.txt_log.delete(1.0, tk.END); self.txt_log.config(state="disabled")
        
        # Lanza el gestor en un hilo separado para que la ventana no se bloquee.
        threading.Thread(target=self._executor_manager, args=(target, ports), daemon=True).start()

    def _executor_manager(self, target, ports):
        """Distribuye el escaneo entre múltiples hilos para ganar velocidad."""
        with ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
            for port in ports:
                if not self.running_flag: break
                executor.submit(self.port_scanner_engine, target, port)
        # Al terminar todos los hilos, ejecuta la finalización.
        self.root.after(0, self._finalize_audit)

    def stop_audit(self):
        """Detiene el bucle de envío de hilos."""
        self.running_flag = False
        self.write_log("[!] ABORTING... WAITING FOR ACTIVE THREADS TO CLEAN UP.")

    def _finalize_audit(self):
        """Gestiona el fin del escaneo y el guardado del reporte."""
        self.running_flag = False
        self.btn_start.set_state("normal"); self.btn_stop.set_state("disabled")

        # Limpia el nombre del archivo de caracteres prohibidos por el sistema.
        filename = re.sub(r'[\\/*?:"<>|]', "", self.entry_filename.get().strip())
        if not filename: filename = Config.DEFAULT_FILENAME
        if not filename.lower().endswith(".txt"): filename += ".txt"

        if messagebox.askyesno("Audit Complete", f"Finished scanning {self.total_count} ports.\nSave results to '{filename}'?"):
            # Comprobación de seguridad para no sobrescribir sin permiso.
            if os.path.exists(filename) and not messagebox.askyesno("Overwrite", "The file already exists. Overwrite?"):
                return

            try:
                # Escritura del archivo de texto.
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(f"AUDIT REPORT FOR: {self.entry_ip.get()}\nDate: {time.ctime()}\n")
                    f.write(f"Ports Scanned: {self.total_count}\n")
                    f.write("-" * 40 + "\n")
                    
                    open_set = set(self.open_ports)
                    
                    if self.var_only_open.get():
                        if not self.open_ports:
                            f.write("No open ports discovered in the audited range.\n")
                        else:
                            for p in sorted(self.open_ports):
                                f.write(f"Port {p}: OPEN\n")
                    else:
                        for p in self.scanned_range:
                            status = "OPEN" if p in open_set else "CLOSED"
                            f.write(f"Port {p}: {status}\n")
                            
                messagebox.showinfo("Export Success", f"Report generated: {filename}")
            except Exception as e:
                messagebox.showerror("IO Error", f"Critical failure writing report: {str(e)}")

# Punto de entrada del programa.
if __name__ == "__main__":
    root = tk.Tk()
    app = ModernPortScanner(root)
    root.mainloop() # Inicia el ciclo de vida de la ventana.