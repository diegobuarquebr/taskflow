# Guia Rápido de Comandos Trivy (apoio ao Encontro 4)

[Trivy](https://aquasec.com/trivy) é um scanner de vulnerabilidades open
source e gratuito, mantido pela Aqua Security. Ele analisa imagens de
container, sistemas de arquivos, repositórios Git e arquivos de
Infraestrutura como Código, procurando por CVEs conhecidas em pacotes de
SO e bibliotecas de linguagem, além de segredos expostos e
configurações inseguras.

Neste curso usamos o Trivy em dois momentos:
- **Módulo 2 (este guia):** escaneamento de imagens Docker.
- **Módulo 3:** SCA (Software Composition Analysis) de dependências.

## Instalação

```bash
# Debian/Ubuntu
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo gpg --dearmor -o /usr/share/keyrings/trivy.gpg
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy

# macOS (Homebrew)
brew install aquasecurity/trivy/trivy

# Via Docker (não precisa instalar nada localmente)
docker run --rm aquasec/trivy image alpine:3.19
```

Consulte a [documentação oficial](https://aquasec.com/trivy) para outras
formas de instalação (binário estático, script de instalação, etc.).

## Comandos usados na aula

### 1. Escaneamento básico de uma imagem

```bash
trivy image taskflow:vuln
```

Escaneia a imagem `taskflow:vuln` (construída a partir do Dockerfile
original e inseguro) e lista todas as vulnerabilidades conhecidas nos
pacotes do sistema operacional e nas bibliotecas instaladas.

### 2. Filtrando por severidade

```bash
# Mostrar somente vulnerabilidades HIGH e CRITICAL
trivy image --severity HIGH,CRITICAL taskflow:vuln
```

Em um pipeline de CI/CD, normalmente não queremos ser bloqueados por
achados de baixa severidade (LOW/MEDIUM) — o foco de gate de segurança
costuma ser HIGH e CRITICAL.

### 3. Definindo formato de saída

```bash
# Saída em formato tabela (padrão, legível no terminal)
trivy image --format table taskflow:vuln

# Saída em JSON (útil para processar com scripts ou outras ferramentas)
trivy image --format json --output resultado.json taskflow:vuln

# Saída em SARIF (formato padrão para integração com GitHub Code Scanning)
trivy image --format sarif --output resultado.sarif taskflow:vuln
```

### 4. Ignorando vulnerabilidades sem correção disponível

```bash
# Mostra apenas vulnerabilidades que já têm um patch/fix disponível
trivy image --ignore-unfixed taskflow:vuln
```

Muito útil na prática: não adianta o time gastar tempo tentando "corrigir"
uma CVE que ainda não tem correção publicada pelo fornecedor.

### 5. Definindo um código de saída para uso em pipelines (gate de segurança)

```bash
# Retorna código de saída 1 (falha) se houver qualquer CRITICAL,
# fazendo o pipeline de CI/CD falhar automaticamente.
trivy image --severity CRITICAL --exit-code 1 taskflow:vuln
```

Essa é a base do que será usado no Módulo 3, quando o Trivy for integrado
a um pipeline de GitHub Actions como gate de SCA.

### 6. Escaneando o Dockerfile em si (misconfiguration)

```bash
trivy config .
```

Executado no diretório do `Dockerfile`, o Trivy também identifica más
práticas na própria escrita do arquivo (ex: uso de `latest`, ausência de
`USER`, etc.), complementando a análise manual feita em aula.

### 7. Comparando "antes" e "depois" (exercício da aula)

```bash
# Imagem original (insegura)
docker build -t taskflow:vuln -f ../../app-exemplo/Dockerfile ../../app-exemplo
trivy image --severity HIGH,CRITICAL taskflow:vuln > antes.txt

# Imagem corrigida (hardened)
docker build -t taskflow:hardened -f Dockerfile.hardened ../../app-exemplo
trivy image --severity HIGH,CRITICAL taskflow:hardened > depois.txt

# Compare a quantidade de linhas/achados
diff antes.txt depois.txt
```

## Referências

- Documentação oficial do Trivy: https://aquasec.com/trivy
- Aqua Security (mantenedora do projeto): https://aquasec.com