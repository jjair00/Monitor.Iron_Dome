import sys
import argparse
import time
import logging
import os, math, re
from daemonize import Daemonize
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import psutil
import time
import magic
import numpy as np
import hashlib
import threading

pid = "/Users/jcueto-r/Desktop/IronDome/irondome.pid"
# files_hash = {}
# files_entropy = {}
# files_type = {}
# files_creation_date = {}
files = []
objects = {}

        #     entropia_anterior = getattr(self, 'entropia_anterior', None)
        #     entropia_actual = calcular_entropia(ruta_archivo)
        #     self.entropia_anterior = entropia_actual
        #     if entropia_anterior is not None:
        #         if entropia_actual > entropia_anterior:
        #             logging.warning(f'Aumento en la entropía detectado en el archivo: {ruta_archivo} con un cambio en la entropía de: {entropia_anterior} a {entropia_actual}.')
        #         elif entropia_actual < entropia_anterior:
        #             logging.warning(f'Disminución en la entropía detectado en el archivo: {ruta_archivo} con un cambio en la entropía de: {entropia_anterior} a {entropia_actual}.')

class Archivo:
    def __init__(self, path, hash, entropy, filetype, creationdate, newhash=None, newentropy=None, newfiletype=None, newcreationdate=None):
        self.path = path
        self.hash = hash
        self.entropy = entropy
        self.filetype = filetype
        self.creationdate = creationdate
        self.newhash = newhash
        self.newentropy = newentropy
        self.newfiletype = newfiletype
        self.newcreationdate = newcreationdate
    
    def __str__(self):
        return f"Archivo: {self.path}, Hash: {self.hash}, Entropy: {self.entropy}, Filetype: {self.filetype}, Creation Date: {self.creationdate}, New Hash: {self.newhash}, New Entropy: {self.newentropy}, New Filetype: {self.newfiletype}, New Creation Date: {self.newcreationdate}"

def starter(ruta, extensiones):
    print("HOLA STARTER")
    path_walk(ruta, extensiones)
    crear_objetos_archivos(files)
    calculate_hash(files)
    # for obj in objects:
    #     print(obj.hash)
    # print(objects.hash)
    # print()
    # started_entropy(files_entropy)
    # get_modified_date(ruta)
    
    # print(files_hash)
    # print(files_entropy)
    # print(files_type)
    # print(files_creation_date)
    # print(files)
    # print(Archivo

def crear_objetos_archivos(files):
    hash1 = "Jasd878fdh78d"
    for file in files:
        i = file
        i = Archivo(i,None,None,None,None,None,None,None,None)
        # print(i)

def path_walk(ruta, extensiones):
    print("HOLA PATH_WALK")
    for dirpath, dirnames, filenames in os.walk(ruta):
        for filename in filenames:
            if len(extensiones) == 0:
                file_path = os.path.join(dirpath, filename)
                files.append(file_path)
                # files_hash[file_path] = None
                # files_entropy[file_path] = None
                # files_creation_date[file_path] = None
            elif len(extensiones) >= 1:
                for a in extensiones:
                    if filename.endswith(a):
                        file_path = os.path.join(dirpath, filename)
                        files.append(file_path)
                        # files_hash[file_path] = None
                        # files_entropy[file_path] = None
                        # files_creation_date[file_path] = None

def calculate_hash(files):
    print("HOLA CALCULATE_HASH")
    for i in files:
        hash_obj = hashlib.md5()
        try:
            with open(i, 'rb') as f:
                for bloque in iter(lambda: f.read(4096), b''):
                    hash_obj.update(bloque)
        except (FileNotFoundError, PermissionError, OSError):
            continue
        # objects[i] = hash_obj.hexdigest()
        # objects[i].hash = hash_obj.hexdigest()
        # i.hash = hash_obj.hexdigest()

def started_entropy(files_entropy):
    print("HOLA STARTED_ENTROPY")
    for file in files_entropy:
        file_type = magic.from_file(file, mime=True)
        with open(file, 'rb') as f:
            content = f.read()
            byte_counts = np.bincount(np.frombuffer(content, dtype=np.uint8))
            probabilities = byte_counts / len(content)
            probabilities = np.where(np.isclose(probabilities, 0), 1e-10, probabilities)  # Reemplazar valores cercanos a cero
            
            files_entropy[file] =  -np.sum(probabilities * np.log2(probabilities))
            files_type[file] = file_type

def get_modified_date(ruta):
    print("HOLA GET_MODIFIED_DATE")
    for i in files_creation_date:
        timestamp = os.path.getmtime(i)
        fecha_creacion = time.ctime(timestamp)
        files_creation_date[i] = fecha_creacion

def monitorizar_ruta(ruta):
    print("HOLA MONITORIZAR_RUTA")
    # time.sleep(4)
    # print("Hola monitorizar")
    event_handler = MyHandler()
    observer = Observer()
    observer.schedule(event_handler, ruta, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

def config_logger():
    print("HOLA CONFIG_LOGGER")
    logging.basicConfig(filename='/Users/jcueto-r/Desktop/IronDome/irondome.log', level=logging.DEBUG, format='%(process)d - %(asctime)s - %(levelname)s - %(message)s - %(name)s')


# def calcular_entropia(ruta):
#     print("HOLA CALCULAR_ENTROPIA")
#     with open(ruta, 'rb') as archivo:
#         datos = archivo.read()
#     tamano = len(datos)
#     contador = {}
#     for byte in datos:
#         if byte not in contador:
#             contador[byte] = 0
#         contador[byte] += 1
#     entropia = 0
#     for count in contador.values():
#         probabilidad = count / tamano
#         entropia -= probabilidad * math.log2(probabilidad)
#     return entropia

def detectar_actividad_criptografica(ruta_archivo):
    print("HOLA DETECTAR_ACTV_CRIPTOGRAFICA")
    with open(ruta_archivo, 'r') as archivo:
        contenido = archivo.read()
    # Ejemplo de detección de actividad criptográfica basado en patrones
    patrones_aes = [
    r'\bAES\b',
    r'\bAdvanced Encryption Standard\b',
    r'\bRijndael\b',
    r'\b128-bit\b',
    r'\b256-bit\b',
    ]
    patrones_3des = [
    r'\b3DES\b',
    r'\bTriple DES\b',
    r'\bTDEA\b',
    r'\b168-bit\b',
    ]
    patrones_rsa = [
    r'\bRSA\b',
    r'\bRivest-Shamir-Adleman\b',
    r'\bPKCS#1\b',
    r'\b2048-bit\b',
    r'\b4096-bit\b',
    ]
    patrones_fernet = [
    r'gAAAAA',  # Encabezado de un archivo Fernet cifrado
    # r'=',    # Fin de un archivo Fernet cifrado
    r'Fernet\.[A-Za-z0-9_-]{43}',              # Cadena de texto en formato de clave Fernet
    r'\.[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{22}'  # Patrón de cadena de texto cifrada con Fernet
    ]

    # Detección de actividad criptográfica basada en patrones
    actividad_criptografica = []
    for patron in patrones_aes:
        if re.search(patron, contenido, re.IGNORECASE):
            actividad_criptografica.append('AES')
            break
    for patron in patrones_3des:
        if re.search(patron, contenido, re.IGNORECASE):
            actividad_criptografica.append('3DES')
            break
    for patron in patrones_rsa:
        if re.search(patron, contenido, re.IGNORECASE):
            actividad_criptografica.append('RSA')
            break
    for patron in patrones_fernet:
        if re.search(patron, contenido, re.IGNORECASE):
            actividad_criptografica.append('FERNET')
            break
    if actividad_criptografica:
        logging.warning(f'Detectada actividad criptográfica en el archivo5: {ruta_archivo}')

def comprobacion_memoria():
    print("HOLA COMPROBACION MEMORIA")
    mem = psutil.Process().memory_info().rss
    pid = os.getpid()
    logging.info(f'Memoria en uso: {format(mem/1024/1024, ".2f")} MB')
    if mem > 300 * 1024 * 1024:
        logging.warning(f'Memoria en uso: {format(mem/1024/1024, ".2f")} MB. Se ha excedido la memoria en uso permitida de 100 MB')
        os.kill(pid,9)




def calculate_entropy(file_path):
    print("HOLA CALCULATE_ENTROPY")
    file_type = magic.from_file(file_path, mime=True)
    with open(file_path, 'rb') as file:
        content = file.read()
        byte_counts = np.bincount(np.frombuffer(content, dtype=np.uint8))
        probabilities = byte_counts / len(content)
        probabilities = np.where(np.isclose(probabilities, 0), 1e-10, probabilities)  # Reemplazar valores cercanos a cero
        entropy = -np.sum(probabilities * np.log2(probabilities))      
    return file_type, entropy

def check_disk_usage(ruta):
    print("Hola CHECK_DISK_USAGE")
    disk_usage = psutil.disk_usage(ruta)
    print(disk_usage)
    # if disk in ['disk0', 'disk2']:
    #     read_count = stats.read_count
    #     write_count = stats.write_count
    #     read_bytes = stats.read_bytes
    #     write_bytes = stats.write_bytes
    #     read_time = stats.read_time
    #     write_time = stats.write_time
    #     print(f"Estadísticas de disco {disk}:")
    #     print(f"Lecturas: {read_count}")
    #     print(f"Escrituras: {write_count}")
    #     print(f"Bytes leídos: {read_bytes}")
    #     print(f"Bytes escritos: {write_bytes}")
    #     print(f"Tiempo de lectura: {read_time}")
    #     print(f"Tiempo de escritura: {write_time}")
    # print(disk_usage)

    if disk_usage is None:
        logging.warning(f'No se encontró la ruta: {ruta}')
        return
    total_reads = disk_usage['disk0'][2] / 1024 / 1024
    total_operations = disk_usage['disk0'][0] + disk_usage['disk0'][1] / 1024 / 1024
    percent = (total_reads / total_operations) * 100
    if percent > 90:
        logging.warning(f'El uso del disco es muy alto: {percent:.2f} %')
    elif percent > 50:
        logging.warning(f'El uso del disco es alto: {percent:.2f} %')
    elif percent > 20:
        logging.warning(f'El uso del disco es medio: {percent:.2f} %')
    elif percent > 2:
        logging.warning(f'El uso del disco es bajo: {percent:.2f} %')
    elif total_operations > 0:
        logging.warning('No se han realizado operaciones de lectura en disco.')
    


class MyHandler(FileSystemEventHandler):
    print("HOLA CLASE MYHANDLER")
    def on_any_event(self, event):
        print("HOLA ON_ANY_EVENT")
        print(event)
        ruta_archivo = event.src_path
        config_logger()
        comprobacion_memoria()
        check_disk_usage(ruta_archivo)
        if os.path.exists(ruta_archivo) and os.path.isfile(ruta_archivo):
            file_type, entropy = calculate_entropy(ruta_archivo)
            logging.info(f'<Path: {ruta_archivo}, File type: {file_type}, Entropy: {entropy}>')

def main():
    print("HOLA MAIN")
    # t0 = time.time()
    parser = argparse.ArgumentParser(description='Programa irondome')
    parser.add_argument('-m', nargs='*', type=str)
    args = parser.parse_args()
    ruta_critica = args.m[0]
    extensiones = args.m[1:]
    # if os.geteuid() != 0:
    #     print("Error: Irondome must be run as root.")
    #     sys.exit(1)

    # h1 = threading.Thread(name="hilo_1", target=starter, args=(ruta_critica, extensiones, ))
    h2 = threading.Thread(name="hilo_2", target=monitorizar_ruta, args=(ruta_critica,))
    starter(ruta_critica, extensiones)
    check_disk_usage(ruta_critica)
    # monitorizar_ruta(ruta_critica)
    
    # h1.start()
    h2.start()
    # h1.join()
    # h2.join()

    print("Hola desde el hilo principal")
    # tf = time.time()
    # td = tf - t0
    # print(td)


if __name__ == "__main__":
    main()
    
    #daemon = Daemonize(app="irondome_analyzer", pid=pid, action=main)
    #daemon.start()

