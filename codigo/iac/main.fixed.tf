# =============================================================================
# main.fixed.tf - Versao CORRIGIDA do exemplo Terraform do Encontro 12.
#
# ATENCAO - mesmo aviso do arquivo main.insecure.tf: este codigo usa o
# provider "aws" apenas para fins de ESTUDO e VALIDACAO (terraform validate
# / terraform plan / Checkov / tfsec). NAO rode "terraform apply" contra
# uma conta AWS real sem entender os custos e implicacoes, a menos que o
# professor oriente especificamente um ambiente de sandbox/free tier
# controlado.
#
# Cada bloco "# CORRIGIDO (FALHA N)" corresponde exatamente a mesma
# numeracao de falha usada em main.insecure.tf. Compare os dois arquivos
# lado a lado durante a aula, e rode Checkov/tfsec nos dois para confirmar
# a reducao de achados.
# =============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Em um projeto real (fora do escopo de "apply" deste curso), o arquivo
  # de estado (terraform.tfstate) deveria usar um backend remoto e
  # criptografado, por dois motivos: (1) permitir que a equipe toda
  # trabalhe sobre o mesmo estado, evitando divergencias; e (2) porque o
  # state pode conter, em texto puro, valores sensiveis de atributos dos
  # recursos criados (ex: uma senha de banco de dados definida via
  # Terraform aparece no state mesmo que venha de uma variavel marcada
  # como "sensitive"). Um backend local (o padrao, usado neste curso) e
  # aceitavel apenas para fins didaticos.
  #
  # Exemplo (comentado, apenas ilustrativo) de backend remoto com um
  # bucket S3 criptografado e trava de concorrencia via DynamoDB:
  #
  # backend "s3" {
  #   bucket         = "minha-empresa-terraform-state"
  #   key            = "taskflow/terraform.tfstate"
  #   region         = "us-east-1"
  #   encrypt        = true
  #   dynamodb_table = "terraform-locks"
  # }
}

provider "aws" {
  region = "us-east-1"
}

# -----------------------------------------------------------------------
# "variable" declara um parametro de entrada do modulo Terraform, que pode
# ser preenchido de fora (linha de comando, arquivo .tfvars, variavel de
# ambiente TF_VAR_*) em vez de ficar fixo ("hardcoded") no codigo.
# -----------------------------------------------------------------------

# CORRIGIDO (FALHA 6, parte 1): em vez de liberar SSH para o mundo inteiro,
# criamos uma variavel para o IP/range que tera permissao de acesso. Em um
# cenario real, este valor viria de um arquivo terraform.tfvars (que NAO
# deve ser commitado se contiver dados sensiveis de rede interna) ou de
# uma variavel de ambiente TF_VAR_ip_permitido_ssh, nunca hardcoded direto
# no .tf versionado.
variable "ip_permitido_ssh" {
  description = "Faixa de IP (CIDR) autorizada a acessar a porta 22 (SSH). Nunca use 0.0.0.0/0 aqui."
  type        = string
  # Valor de exemplo apenas para fins didaticos (representa "nenhum IP
  # externo, somente dentro da propria rede privada 10.0.0.0/16"). Em um
  # projeto real, isso seria o IP publico da VPN corporativa ou de um
  # bastion host, por exemplo - nunca um range aberto.
  default = "10.0.0.0/16"
}

# -----------------------------------------------------------------------
# RECURSO 1: bucket de armazenamento de objetos (S3) - versao corrigida
# -----------------------------------------------------------------------
resource "aws_s3_bucket" "relatorios_taskflow" {
  bucket = "taskflow-relatorios-exemplo-curso-devsecops"

  # CORRIGIDO (FALHA 1): tags de governanca, permitindo identificar dono,
  # ambiente e projeto do recurso em uma conta com muitos buckets.
  tags = {
    Projeto  = "taskflow-devsecops-curso"
    Ambiente = "estudo"
    Owner    = "disciplina-devsecops"
  }
}

# CORRIGIDO (FALHA 2): bloqueio de acesso publico REATIVADO em todas as
# quatro dimensoes. Este e o principal mecanismo de defesa da AWS contra
# buckets tornados publicos por engano (via ACL ou via policy) - deve
# estar habilitado por padrao em praticamente qualquer bucket que nao
# tenha uma justificativa de negocio explicita para ser publico (ex: um
# site estatico publico, o que nao e o caso aqui).
resource "aws_s3_bucket_public_access_block" "relatorios_taskflow" {
  bucket = aws_s3_bucket.relatorios_taskflow.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# CORRIGIDO (FALHA 3): ACL alterada de "public-read" para "private" - por
# padrao, apenas o dono do bucket (a propria conta AWS) tem acesso aos
# objetos. Qualquer acesso adicional deveria ser concedido de forma
# explicita e minima via IAM policy, nunca via ACL publica.
resource "aws_s3_bucket_acl" "relatorios_taskflow" {
  bucket = aws_s3_bucket.relatorios_taskflow.id
  acl    = "private"

  depends_on = [aws_s3_bucket_public_access_block.relatorios_taskflow]
}

# CORRIGIDO (FALHA 4): criptografia em repouso habilitada explicitamente,
# usando AES-256 gerenciado pela propria AWS (SSE-S3). Em ambientes com
# requisitos de compliance mais rigorosos, o ideal seria usar SSE-KMS com
# uma chave gerenciada pelo cliente (aws:kms), o que da controle adicional
# sobre rotacao e revogacao de chaves.
resource "aws_s3_bucket_server_side_encryption_configuration" "relatorios_taskflow" {
  bucket = aws_s3_bucket.relatorios_taskflow.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# CORRIGIDO (FALHA 5): versionamento habilitado. Agora, um DELETE ou um
# PUT que sobrescreve um objeto existente gera uma nova versao em vez de
# destruir a anterior - permitindo recuperacao em caso de erro operacional
# ou de um ataque que tente apagar/corromper dados.
resource "aws_s3_bucket_versioning" "relatorios_taskflow" {
  bucket = aws_s3_bucket.relatorios_taskflow.id

  versioning_configuration {
    status = "Enabled"
  }
}

# -----------------------------------------------------------------------
# RECURSO 2: Security Group - versao corrigida
# -----------------------------------------------------------------------
resource "aws_security_group" "taskflow_app_sg" {
  name        = "taskflow-app-sg-corrigido"
  description = "Security group de exemplo (CORRIGIDO) para o Encontro 12"

  # CORRIGIDO (FALHA 6, parte 2): a porta 22 agora e liberada apenas para
  # a faixa de IP definida na variavel "ip_permitido_ssh" (por padrao,
  # uma rede privada de exemplo), nunca mais para 0.0.0.0/0. Em um cenario
  # real de producao, o ideal e ir alem: usar um bastion host, VPN, ou
  # AWS Systems Manager Session Manager, eliminando a necessidade de expor
  # a porta 22 publicamente mesmo que restrita por IP.
  ingress {
    description = "SSH liberado somente para a faixa de IP autorizada (variavel)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.ip_permitido_ssh]
  }

  # CORRIGIDO (FALHA 7): trafego de saida tambem restrito - liberamos
  # apenas HTTPS (443), o minimo necessario para, por exemplo, a instancia
  # baixar atualizacoes de pacotes ou se comunicar com APIs externas via
  # TLS. Ajuste conforme a necessidade real da aplicacao (o objetivo aqui
  # e demonstrar o principio de menor privilegio, nao uma regra universal).
  egress {
    description = "Saida HTTPS apenas"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Projeto = "taskflow-devsecops-curso"
  }
}

# -----------------------------------------------------------------------
# "output" expõe valores calculados/criados pelo Terraform para quem
# consome este modulo (outro modulo, um pipeline de CI, ou a saida do
# terminal apos "terraform apply"). Aqui, expomos o nome do bucket e o id
# do security group, uteis para referenciar estes recursos em outro lugar
# sem precisar redigitar os nomes.
# -----------------------------------------------------------------------
output "nome_bucket_relatorios" {
  description = "Nome do bucket S3 de relatorios do TaskFlow"
  value       = aws_s3_bucket.relatorios_taskflow.bucket
}

output "id_security_group_app" {
  description = "ID do security group da aplicacao TaskFlow"
  value       = aws_security_group.taskflow_app_sg.id
}

# -----------------------------------------------------------------------
# Resumo das correcoes aplicadas nesta versao (ver Encontro 12):
#   FALHA 1 -> tags de governanca adicionadas
#   FALHA 2 -> bloqueio de acesso publico reativado (todos os 4 campos true)
#   FALHA 3 -> ACL alterada de "public-read" para "private"
#   FALHA 4 -> criptografia em repouso (SSE-S3/AES256) habilitada
#   FALHA 5 -> versionamento do bucket habilitado
#   FALHA 6 -> SSH restrito a variavel "ip_permitido_ssh" (nunca 0.0.0.0/0)
#   FALHA 7 -> egress restrito a HTTPS (443) em vez de todo o trafego
# -----------------------------------------------------------------------
