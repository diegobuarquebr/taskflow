# Stack de observabilidade local para o Modulo 6.
#
# Sobe tres servicos, todos open source e gratuitos:
#   - Grafana  : interface web para consultar e visualizar os logs
#   - Loki     : banco de dados de logs (armazena e indexa)
#   - Promtail : agente que le os arquivos de log da aplicacao e envia
#                para o Loki
#
# Abordagem escolhida para esta aula: a aplicacao TaskFlow roda
# DIRETAMENTE no host (fora do Docker, via `python app_instrumented.py`,
# como nos outros encontros do curso) e grava logs em
# `codigo/logs/taskflow.log`. O Promtail, rodando em container, monta
# essa mesma pasta como volume e le o arquivo de fora para dentro.
#
# Por que essa abordagem (arquivo em disco) em vez de container+stdout?
#   - E a forma mais simples de configurar em uma aula de 3h: nao exige
#     containerizar a aplicacao Flask, nem lidar com Docker networking
#     entre o container da app e o Promtail.
#   - Fica identico ao fluxo mais comum em ambientes reais on-prem/VM,
#     onde agentes de coleta (Promtail, Filebeat, Fluentd) leem arquivos
#     de log em disco.
#   - Quem quiser aprofundar: e possivel adaptar facilmente para o
#     Promtail ler logs via `docker logs` (usando o driver de logging
#     `json-file` do Docker) - fica como desafio opcional.
#
# Como usar:
#   1. Em um terminal: python app_instrumented.py   (gera codigo/logs/taskflow.log)
#   2. Em outro terminal, dentro de modulo-06-observabilidade-resposta/codigo:
#        docker compose up -d
#   3. Acesse o Grafana em http://localhost:3000 (usuario/senha: admin/admin)
#   4. Adicione o Loki como data source (URL: http://loki:3100) - ou use
#      o provisionamento automatico ja incluido abaixo.

version: "3.8"

services:
  loki:
    image: grafana/loki:2.9.6
    container_name: taskflow-loki
    ports:
      - "3100:3100"
    command: -config.file=/etc/loki/local-config.yaml
    networks:
      - observabilidade

  promtail:
    image: grafana/promtail:2.9.6
    container_name: taskflow-promtail
    volumes:
      # Monta a pasta de logs da aplicacao (gerada pelo app_instrumented.py
      # rodando no host) como somente leitura dentro do container.
      - ./logs:/var/log/taskflow:ro
      - ./promtail-config.yml:/etc/promtail/config.yml:ro
    command: -config.file=/etc/promtail/config.yml
    depends_on:
      - loki
    networks:
      - observabilidade

  grafana:
    image: grafana/grafana:10.4.2
    container_name: taskflow-grafana
    ports:
      - "3000:3000"
    environment:
      # Credenciais simples para ambiente de laboratorio/aula.
      # NUNCA use usuario/senha padrao (admin/admin) em ambientes reais.
      - GF_SECURITY_ADMIN_USER=admin
      - GF_SECURITY_ADMIN_PASSWORD=admin
      # Evita a tela de "troque sua senha" no primeiro acesso, para
      # agilizar a demonstracao em aula.
      - GF_SECURITY_ADMIN_PASSWORD_CHANGE_DISABLED=true
      # Provisiona o Loki automaticamente como data source, para que
      # o aluno nao precise configurar isso manualmente na UI.
      - GF_INSTALL_PLUGINS=
    volumes:
      - ./grafana-provisioning/datasources:/etc/grafana/provisioning/datasources:ro
    depends_on:
      - loki
    networks:
      - observabilidade

networks:
  observabilidade:
    driver: bridge