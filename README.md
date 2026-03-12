# 🛡️ Port Auditer by Jacsaw

![Versión](https://img.shields.io/badge/Versi%C3%B3n-2.0-F700FF?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.10+-141414?style=for-the-badge&logo=python)
![Nmap](https://img.shields.io/badge/Engine-Nmap-white?style=for-the-badge&logo=nmap)

**Port Auditer** es una herramienta de auditoría de red de alto rendimiento con una interfaz gráfica bonita y con mi toque morado de siempre. Diseñada para identificar puertos abiertos de forma rápida y visual, facilitando la exportación de resultados para informes profesionales.

---

## 🚀 Características Principales

* **Escaneo Optimizado:** Filtra automáticamente los puertos cerrados para mostrar solo los **OPEN**, mejorando la claridad y el rendimiento.
* **Motor Nmap:** Utiliza la potencia del motor de escaneo industrial Nmap.
* **Intensidad Variable:** Selector de potencia (T1 a T5) para controlar la velocidad y el impacto en la red.
* **Exportación Multiformato:** Genera reportes en **Excel (.xlsx), JSON, PDF o Texto Plano**.
* **Documentación Educativa:** Código fuente 100% comentado línea a línea para que incluso personas sin conocimientos de programación entiendan el flujo.

---

## 📋 Requisitos e Instalación

### 1. Motor Nmap (Esencial)
El programa utiliza Nmap para funcionar. A diferencia de las librerías, Nmap **debe estar instalado en el sistema**:
* **Instalación:** Descarga el instalador de Windows (`.exe`) desde [https://nmap.org/download.html](https://nmap.org/download.html).
* **Configuración:** Durante la instalación, asegúrate de dejar marcada la opción de instalar **Npcap**. El programa intentará localizar Nmap automáticamente en las rutas por defecto si no está en el PATH.

### 2. Python y Librerías
* **Python 3.10 o superior** (marcar "Add Python to PATH" al instalar).
* **Auto-Instalación:** Al ejecutar el programa por primera vez, este detectará e instalará automáticamente las siguientes dependencias de Python:
  * `pandas` (Gestión de datos)
  * `openpyxl` (Soporte para Excel)
  * `fpdf` (Generación de PDFs)

---

## ⚙️ Instrucciones de Uso

1.  **Ejecución:** Abre una terminal en la carpeta del archivo y escribe:
    ```bash
    python scan.py
    ```
2.  **Privilegios:** El sistema solicitará **permisos de administrador** mediante una ventana emergente de Windows. Esto es obligatorio para que el motor de escaneo pueda analizar los puertos.
3.  **Configuración del escaneo:**
    * **Target:** IP del objetivo (ej. `192.168.1.1`).
    * **Rango:** Puertos específicos (ej. `80,443,3306`) o rangos (ej. `1-1000`).
    * **Power:** A mayor nivel, más rápido el escaneo pero mayor consumo de CPU.
4.  **Reporte:** Al finalizar, el programa te ofrecerá guardar el archivo y lo abrirá automáticamente.

---

## 🛠️ Estructura del Software

Para facilitar el aprendizaje, el código está organizado en bloques claros:
* **Preparación:** Gestión automática de librerías faltantes.
* **Seguridad:** Elevación de privilegios para Windows.
* **Diseño:** Interfaz gráfica personalizada con botones redondeados y colores Cyberpunk.
* **Motor:** Captura de datos en tiempo real desde el proceso del sistema.

---

## ⚠️ Aviso de Responsabilidad (Disclaimer)

Esta herramienta ha sido creada exclusivamente con fines **educativos y de auditoría ética**. El uso de este software contra sistemas sin autorización previa es ilegal. El desarrollador no se hace responsable del mal uso de la herramienta.

---

**Desarrollado con ❤️ por Jacsaw**