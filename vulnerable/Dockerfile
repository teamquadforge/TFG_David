FROM ubuntu:22.04

RUN apt update && apt install -y openssh-server

RUN mkdir /var/run/sshd

# Password root
RUN echo 'root:root' | chpasswd

# Permitir root login
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# 🔥 CLAVE: logs a stdout
RUN sed -i 's/#LogLevel INFO/LogLevel VERBOSE/' /etc/ssh/sshd_config

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]