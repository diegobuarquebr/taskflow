# Dockerfile INSEGURO - linha de base usada no Modulo 2 (Hardening).
# Cada comentario "# FALHA" indica uma pratica que sera corrigida
# durante a aula de hardening de containers.

# FALHA 1: tag "latest" nao fixada -> build nao reprodutivel e pode
# puxar uma imagem base com vulnerabilidades novas sem aviso.
FROM python:latest

# FALHA 2: executando como root (nenhum USER definido).
WORKDIR /app

COPY requirements.txt .

# FALHA 3: nenhuma verificacao de integridade / hash das dependencias.
RUN pip install -r requirements.txt

COPY . .

# FALHA 4: segredo passado como ARG/ENV fica gravado nas camadas
# da imagem e pode ser extraido com "docker history".
ENV ADMIN_PASSWORD=admin123

# FALHA 5: expondo a porta do servidor de desenvolvimento do Flask,
# que nao e apto para producao.
EXPOSE 5000

# FALHA 6: container roda com debug habilitado e como root.
CMD ["python", "app.py"]
