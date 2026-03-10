===========================================================
            PORT AUDITOR - GUÍA DE INSTALACIÓN
===========================================================

DESCRIPCIÓN:
Este software es un auditor de puertos TCP de alto rendimiento
con interfaz gráfica, capaz de escanear el espectro completo 
(65535 puertos) mediante multihilo (Multi-threading).

REQUISITOS PREVIOS:
1. Tener instalado Python 3.x (se recomienda 3.10 o superior).
2. Durante la instalación de Python en Windows, asegúrese de 
   marcar la casilla "tcl/tk and IDLE" para que la interfaz 
   gráfica (Tkinter) funcione correctamente.
   Si no, tendrá que instalar la dependencia posteriormente.
   (Para ver todas las dependencias necesarias descarguese DEPENDENCIAS.txt y abre el archivo)

PASOS PARA LA EJECUCIÓN:
1. Descargue el archivo 'scan.py'.
2. Abra una terminal (CMD o PowerShell) en la carpeta donde 
   se encuentra el archivo.

3. Inicie la aplicación con el comando:
   
   "python scan.py" o "python3 scan.py"

NOTAS DE USO:
- Modo Manual: Permite rangos (ej. 20-80) o listas (ej. 80,443).
- Rendimiento: El valor MAX_WORKERS en el código define la 
  velocidad. 800 hilos es ideal para la mayoría de sistemas.
- Reportes: Los archivos de texto se generarán en la misma 
  carpeta del programa.

IMPORTANTE:
   Si el programa no abre, revisa DEPENDENCIAS.txt
   USTED es responsable del uso que le das a esta herramienta
   
===========================================================
                Desarrollado por Jacsaw
===========================================================