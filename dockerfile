FROM python:3.7.16

# Instalar paquetes necesarios
RUN apt-get update && apt-get install -y \
    sudo 
    # python3\
    # python3-pip

RUN pip install daemonize
RUN pip install watchdog
RUN pip install psutil
RUN pip install numpy
RUN pip install python-magic
RUN pip install libmagic
RUN pip install cryptography

# Crear usuario
RUN useradd -m jcueto-r && \
    echo "jcueto-r:password" | chpasswd
RUN usermod -aG sudo jcueto-r

# USER jcueto-r
USER root
COPY irondome.py /home/jcueto-r/irondome.py
COPY remove.py /home/jcueto-r/remove.py
RUN mkdir /home/jcueto-r/prueba
COPY prueba /home/jcueto-r/prueba
RUN mkdir /var/log/irondome/
RUN sudo chmod 700 /var/log/irondome/
RUN sudo chmod 700 /home/jcueto-r/irondome.py
RUN sudo chmod 700 /home/jcueto-r/remove.py


# RUN sudo chown jcueto-r /home/infection/
# RUN sudo chown -R jcueto-r /home/infection/

# COPY stockholm.py /home/jcueto-r/stockholm.py
# COPY infection /home/jcueto-r/infection


# EXPOSE 80
# EXPOSE 4242

# # Iniciar servicios con cmd o entrypoint
# CMD service ssh start && nginx -g 'daemon off;' && tor