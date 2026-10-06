# =============================================================================
# main.insecure.tf - Exemplo Terraform INSEGURO usado no Encontro 12.
#
# ATENCAO - LEIA ANTES DE RODAR QUALQUER COMANDO:
#   Este arquivo usa o provider "aws" apenas para fins de ESTUDO e
#   VALIDACAO DE CODIGO (terraform validate / terraform plan / scanners
#   como Checkov e tfsec). NAO faca "terraform apply" deste arquivo contra
#   uma conta AWS real, a menos que:
#     (a) voce entenda completamente os custos e implicacoes de cada
#         recurso criado, e
#     (b) o professor tenha orientado especificamente o uso de um ambiente
#         de sandbox/free tier controlado para isso.
#   Para rodar `terraform plan` sem qualquer credencial AWS real, veja a
#   observacao de "credenciais fake" mais abaixo, ou utilize o provider
#   alternativo "docker" descrito no material teorico do Encontro 12.
#
# Cada bloco de recurso abaixo contem uma ou mais falhas de configuracao
# de seguranca DE PROPOSITO, marcadas com "# FALHA", para serem
# encontradas primeiro manualmente e depois com Checkov/tfsec.
# =============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# O provider declara COM QUAL nuvem/API o Terraform vai conversar e em qual
# regiao. Para rodar apenas "terraform validate" (que checa somente a
# sintaxe e a consistencia interna do codigo, sem contatar a AWS) nao e
# necessario ter credenciais validas. Para "terraform plan" (que de fato
# consulta a AWS para saber o que ja existe), seria necessario configurar
# credenciais - o que o curso evita propositalmente, focando o Encontro 12
# em leitura de codigo e nos scanners estaticos (Checkov/tfsec), que NAO
# precisam de credenciais nem de contato com a nuvem real.
provider "aws" {
  region = "us-east-1"
}

# -----------------------------------------------------------------------
# RECURSO 1: bucket de armazenamento de objetos (S3)
# -----------------------------------------------------------------------
# "resource" declara uma peca de infraestrutura que o Terraform deve
# criar e gerenciar. O formato geral e:
#   resource "<tipo_do_recurso>" "<nome_local>" { ...argumentos... }
resource "aws_s3_bucket" "relatorios_taskflow" {
  bucket = "taskflow-relatorios-exemplo-curso-devsecops"

  # FALHA 1: nenhuma tag de identificacao/ambiente/dono. Sem tags, em um
  # ambiente real com dezenas de buckets, fica dificil saber para que serve
  # cada recurso, quem e o responsavel, e se pode ser apagado com seguranca.
  # (Isso e mais uma boa pratica de governanca do que uma falha critica de
  # seguranca, mas vale mencionar em aula.)
}

# FALHA 2: controle de acesso publico do bucket todo DESABILITADO. O bloco
# "aws_s3_bucket_public_access_block" e o mecanismo que a AWS oferece para
# IMPEDIR que um bucket seja tornado publico por engano (por ACL ou por
# policy). Ao definir todos os quatro campos como "false", este codigo
# desativa essa protecao de proposito - exatamente o tipo de erro que,
# historicamente, causou diversos vazamentos de dados em incidentes reais
# de buckets S3 mal configurados.
resource "aws_s3_bucket_public_access_block" "relatorios_taskflow" {
  bucket = aws_s3_bucket.relatorios_taskflow.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# FALHA 3: ACL definida explicitamente como "public-read" - qualquer
# pessoa na internet, sem autenticacao nenhuma, consegue LISTAR e BAIXAR
# todos os objetos deste bucket.
resource "aws_s3_bucket_acl" "relatorios_taskflow" {
  bucket = aws_s3_bucket.relatorios_taskflow.id
  acl    = "public-read"

  depends_on = [aws_s3_bucket_public_access_block.relatorios_taskflow]
}

# FALHA 4: nenhum bloco de criptografia em repouso (server-side encryption)
# configurado para o bucket. Sem isso, os objetos sao armazenados sem
# criptografia adicional gerenciada (dependendo da configuracao da conta,
# pode nao haver nenhuma camada extra de protecao dos dados em repouso).
# (Propositalmente, nao ha nenhum bloco "aws_s3_bucket_server_side_encryption_configuration" aqui.)

# FALHA 5: nenhum bloco de versionamento configurado. Sem versionamento,
# um "DELETE" ou um "PUT" que sobrescreve um objeto e IRREVERSIVEL - nao
# ha como recuperar a versao anterior em caso de erro operacional ou de um
# ataque (ex: ransomware que sobrescreve arquivos).
# (Propositalmente, nao ha nenhum bloco "aws_s3_bucket_versioning" aqui.)

# -----------------------------------------------------------------------
# RECURSO 2: Security Group (firewall de rede) para uma instancia EC2
# hipotetica que serviria a aplicacao TaskFlow
# -----------------------------------------------------------------------
resource "aws_security_group" "taskflow_app_sg" {
  name        = "taskflow-app-sg-inseguro"
  description = "Security group de exemplo (INSEGURO) para o Encontro 12"

  # FALHA 6: porta 22 (SSH) liberada para 0.0.0.0/0 - ou seja, QUALQUER
  # endereco IP na internet inteira pode tentar se conectar via SSH a
  # instancia. Isso expõe a instancia a tentativas de forca bruta e
  # exploracao automatizada assim que ela recebe um IP publico, mesmo que
  # a senha/chave seja forte - a superficie de ataque exposta e desnecessaria.
  ingress {
    description = "SSH liberado para o mundo inteiro (FALHA)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # FALHA 7: trafego de saida (egress) tambem liberado sem nenhuma
  # restricao. Isso nao e sempre um erro grave (egress amplo e comum), mas
  # combinado com a FALHA 6, se a instancia for comprometida via SSH, o
  # invasor tem saida de rede irrestrita para exfiltrar dados ou baixar
  # ferramentas adicionais de ataque.
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Projeto = "taskflow-devsecops-curso"
  }
}

# -----------------------------------------------------------------------
# Resumo das falhas propositais deste arquivo (ver Encontro 12):
#   FALHA 1 -> bucket sem tags de governanca
#   FALHA 2 -> bloqueio de acesso publico desabilitado
#   FALHA 3 -> ACL publica (public-read)
#   FALHA 4 -> sem criptografia em repouso configurada
#   FALHA 5 -> sem versionamento habilitado
#   FALHA 6 -> security group com SSH (22) aberto para 0.0.0.0/0
#   FALHA 7 -> egress totalmente irrestrito
# -----------------------------------------------------------------------
