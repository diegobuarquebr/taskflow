#!/usr/bin/env bash
# =============================================================================
# docker-run-seguro.sh
#
# Script de apoio ao Encontro 4 (Hardening de Containers Docker).
# Demonstra como rodar a imagem "hardened" da TaskFlow com flags de
# seguranca adicionais em tempo de EXECUCAO (complementam o que ja foi
# corrigido no Dockerfile.hardened, mas atuam na camada do runtime/orquestrador).
#
# Uso:
#   1. Construa a imagem hardened primeiro:
#        docker build -t taskflow:hardened -f Dockerfile.hardened ../../app-exemplo
#   2. Rode este script:
#        ./docker-run-seguro.sh
# =============================================================================

set -euo pipefail

IMAGE_NAME="taskflow:hardened"
CONTAINER_NAME="taskflow-seguro"

# Volume nomeado para persistir o banco SQLite fora do sistema de arquivos
# do container. Necessario porque vamos rodar o container com
# --read-only, o que impede qualquer escrita no filesystem da imagem,
# EXCETO nos caminhos explicitamente montados como graváveis (--tmpfs
# ou -v). A aplicacao precisa gravar o arquivo taskflow.db em algum lugar.
VOLUME_NAME="taskflow-dados"

docker volume create "$VOLUME_NAME" >/dev/null

# --read-only: torna o filesystem raiz do container somente leitura.
# Se um atacante conseguir executar codigo dentro do container (ex: via
# uma vulnerabilidade de aplicacao), ele nao consegue alterar binarios,
# instalar ferramentas adicionais nem persistir malware no filesystem
# da imagem.
#
# Como o filesystem fica read-only, precisamos montar explicitamente os
# unicos diretorios que a aplicacao realmente precisa escrever: o
# diretorio de dados (banco SQLite) via volume nomeado, e /tmp via tmpfs
# (memoria volatil, some quando o container para).
#
# --cap-drop=ALL: remove TODAS as Linux capabilities do container
# (ex: CAP_NET_RAW, CAP_SYS_ADMIN, etc.), que por padrao o Docker concede
# um subconjunto. A aplicacao TaskFlow (um servidor HTTP Python comum)
# nao precisa de nenhuma capability especial para funcionar, entao
# zeramos tudo. Se algum dia precisar de uma capability especifica,
# adicione so ela com --cap-add=NOME_DA_CAPABILITY.
#
# --security-opt=no-new-privileges: impede que qualquer processo dentro
# do container obtenha mais privilegios do que tinha ao iniciar (ex: via
# binarios com bit SUID). Isso fecha uma tecnica comum de escalonamento
# de privilegios mesmo se um binario SUID malicioso existir na imagem.
#
# --privileged NUNCA e usado aqui de proposito: esse modo da acesso quase
# total ao host e so deveria existir em casos muito especificos e bem
# justificados (nao e o caso desta aplicacao).
#
# --memory / --cpus: limitam recursos para reduzir o impacto de um
# possivel abuso (ex: negacao de servico por consumo excessivo).
#
# --user: roda como usuario nao-root (redundante com o USER definido no
# Dockerfile.hardened, mas explicito aqui por clareza e defesa em
# profundidade - garante que, mesmo que a imagem mude, o runtime nao
# permita root).
#
# -p: publica a porta da aplicacao no host. Em producao real, o ideal e
# colocar um proxy reverso (nginx, Traefik) na frente e nao expor a
# porta da aplicacao diretamente.
#
# -e ADMIN_PASSWORD: segredo injetado em tempo de execucao via variavel
# de ambiente, NUNCA gravado no Dockerfile (ver FALHA 4 corrigida em
# Dockerfile.hardened). Em um ambiente real, isso viria de um cofre de
# segredos (Vault, AWS Secrets Manager, Docker/K8s secrets), nao de texto
# puro na linha de comando como fazemos aqui apenas para fins didaticos.
docker run \
  --name "$CONTAINER_NAME" \
  --rm \
  -d \
  --read-only \
  -v "${VOLUME_NAME}:/app/data" \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --memory="256m" \
  --cpus="0.5" \
  --user taskflow \
  -p 5000:5000 \
  -e ADMIN_PASSWORD="troque-este-valor-em-tempo-de-execucao" \
  "$IMAGE_NAME"

echo "Container '$CONTAINER_NAME' iniciado a partir da imagem '$IMAGE_NAME'."
echo "Verifique com: docker ps --filter name=$CONTAINER_NAME"
echo "Logs com:      docker logs -f $CONTAINER_NAME"