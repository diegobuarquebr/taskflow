"""
TaskFlow - Versao IaC (Docker Compose + PostgreSQL).

Este arquivo e derivado de app.py (versao corrigida apos o Modulo 3) com UMA
mudanca de arquitetura: em vez de SQLite local (arquivo taskflow.db dentro do
container), a aplicacao passa a usar o PostgreSQL levantado pelo servico "db"
do docker-compose.secure.yml.

Por que isso era necessario:
  - O servico "web" roda com `read_only: true`. Com o filesystem raiz somente
    leitura, o sqlite3.connect("taskflow.db") nao consegue criar o arquivo e
    falha com "sqlite3.OperationalError: unable to open database file".
  - Com o banco no Postgres, o container "web" nao precisa gravar nada em
    disco, o que e coerente com o hardening (read_only, redes isoladas,
    healthcheck do banco, depends_on: service_healthy).

O que mudou em relacao ao app.py:
  1. sqlite3 -> psycopg2 (driver do PostgreSQL).
  2. A conexao vem da variavel de ambiente DATABASE_URL (a mesma que o
     docker-compose.secure.yml ja injeta), sem fallback silencioso.
  3. Placeholders "?" -> "%s" (padrao do psycopg2). As queries continuam
     PARAMETRIZADAS: a correcao do SQL Injection (vuln. #1) foi mantida.
  4. DDL: INTEGER PRIMARY KEY AUTOINCREMENT -> SERIAL PRIMARY KEY, e
     executescript() -> execute() (o psycopg2 aceita varios comandos em um
     unico execute() quando nao ha parametros).
  5. Linhas retornam como dicionario via RealDictCursor (equivalente ao
     sqlite3.Row usado antes).
  6. O seed de usuarios e idempotente (ON CONFLICT DO NOTHING) e a conexao
     inicial tem retentativas, caso o banco ainda esteja subindo.

Mantidos DE PROPOSITO (escopo do Modulo 4 - DAST / OWASP Top 10):
  - XSS armazenado na descricao das tarefas.
  - Endpoint /debug/info exposto.
  - debug=True no app.run().

Variaveis de ambiente obrigatorias:
  - TASKFLOW_SECRET_KEY : chave de sessao do Flask.
  - DATABASE_URL        : ex. postgresql://usuario:senha@db:5432/taskflow

Dependencia nova (adicionar ao requirements.txt):
  - psycopg2-binary
"""

import os
import time

import psycopg2
import psycopg2.extras

from flask import Flask, g, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

# -----------------------------------------------------------------------------
# CORRECAO da Vulnerabilidade #3: SECRET_KEY hardcoded.
#
# O valor vem de uma variavel de ambiente (nunca commitada no repositorio).
# Se a variavel nao existir, a aplicacao falha explicitamente na inicializacao
# em vez de "cair para tras" silenciosamente em um valor fixo.
# -----------------------------------------------------------------------------
app = Flask(__name__)

_secret_key = os.environ.get("TASKFLOW_SECRET_KEY")
if not _secret_key:
    raise RuntimeError(
        "Variavel de ambiente TASKFLOW_SECRET_KEY nao foi definida. "
        "Configure-a antes de iniciar a aplicacao "
        "(ex: export TASKFLOW_SECRET_KEY='valor-aleatorio-e-longo')."
    )
app.config["SECRET_KEY"] = _secret_key

# -----------------------------------------------------------------------------
# Conexao com o PostgreSQL.
#
# Mesma filosofia da SECRET_KEY: sem fallback silencioso. Se DATABASE_URL nao
# estiver definida, a aplicacao falha na inicializacao com uma mensagem clara.
# No docker-compose.secure.yml ela e montada a partir do .env:
#   postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@db:5432/${POSTGRES_DB}
# -----------------------------------------------------------------------------
DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError(
        "Variavel de ambiente DATABASE_URL nao foi definida. "
        "Ex: postgresql://usuario:senha@db:5432/taskflow"
    )

DB_CONNECT_RETRIES = 10
DB_CONNECT_DELAY_SECONDS = 2


def _connect_with_retry():
    """Abre a conexao com o Postgres, tentando de novo se o banco ainda
    estiver iniciando (o healthcheck do compose ja ajuda, mas nao custa ser
    resiliente fora do Compose)."""
    last_error = None
    for attempt in range(1, DB_CONNECT_RETRIES + 1):
        try:
            return psycopg2.connect(
                DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor
            )
        except psycopg2.OperationalError as exc:
            last_error = exc
            print(
                f"[db] tentativa {attempt}/{DB_CONNECT_RETRIES} falhou: {exc}",
                flush=True,
            )
            time.sleep(DB_CONNECT_DELAY_SECONDS)
    raise last_error


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = _connect_with_retry()
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    with db.cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tasks (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                done INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users (id)
            );
            """
        )
    db.commit()

    with db.cursor() as cur:
        cur.execute("SELECT COUNT(*) AS total FROM users")
        total = cur.fetchone()["total"]

        if total == 0:
            # -----------------------------------------------------------------
            # CORRECAO da Vulnerabilidade #4: senha em texto puro.
            #
            # Antes: INSERT ... ("admin", "admin123")
            #
            # Depois: generate_password_hash() do Werkzeug armazena apenas o
            # HASH (com salt automatico), nunca a senha em si.
            #
            # ON CONFLICT DO NOTHING torna o seed idempotente: se dois
            # processos (ex: reloader do debug) tentarem semear ao mesmo
            # tempo, nao ha erro de chave duplicada.
            # -----------------------------------------------------------------
            cur.execute(
                "INSERT INTO users (username, password) VALUES (%s, %s) "
                "ON CONFLICT (username) DO NOTHING",
                ("admin", generate_password_hash("admin123")),
            )
            cur.execute(
                "INSERT INTO users (username, password) VALUES (%s, %s) "
                "ON CONFLICT (username) DO NOTHING",
                ("aluno", generate_password_hash("senha123")),
            )
    db.commit()


@app.route("/")
def index():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return redirect(url_for("tasks"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # ---------------------------------------------------------------------
        # CORRECAO da Vulnerabilidade #1: SQL Injection no login.
        #
        # A query e PARAMETRIZADA: o driver (agora psycopg2, com placeholders
        # "%s") trata "username" sempre como DADO, nunca como parte do comando
        # SQL. Nunca monte a query com f-string/concatenacao/%-formatting.
        # ---------------------------------------------------------------------
        db = get_db()
        with db.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cur.fetchone()

        # ---------------------------------------------------------------------
        # Ajuste necessario por causa da correcao da Vulnerabilidade #4:
        # a senha esta armazenada como hash, entao usamos check_password_hash()
        # em vez de comparar "password == user['password']".
        # ---------------------------------------------------------------------
        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("tasks"))
        error = "Usuario ou senha invalidos."

    return f"""
    <h1>TaskFlow - Login</h1>
    <form method="post">
        Usuario: <input type="text" name="username"><br>
        Senha: <input type="password" name="password"><br>
        <input type="submit" value="Entrar">
    </form>
    <p style="color:red">{error or ""}</p>
    """


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/tasks", methods=["GET"])
def tasks():
    if "user_id" not in session:
        return redirect(url_for("login"))

    search = request.args.get("q", "")
    db = get_db()

    with db.cursor() as cur:
        if search:
            # -----------------------------------------------------------------
            # CORRECAO da Vulnerabilidade #1 (variante): SQL Injection na
            # busca de tarefas.
            #
            # O padrao do LIKE tambem e passado como parametro: montamos
            # "%termo%" em Python e o enviamos inteiro como UM unico "%s".
            # O Postgres nunca interpreta o conteudo de "search" como SQL.
            # -----------------------------------------------------------------
            like_pattern = f"%{search}%"
            cur.execute(
                "SELECT * FROM tasks WHERE user_id = %s AND title LIKE %s",
                (session["user_id"], like_pattern),
            )
        else:
            cur.execute(
                "SELECT * FROM tasks WHERE user_id = %s", (session["user_id"],)
            )
        rows = cur.fetchall()

    items = ""
    for row in rows:
        # ---------------------------------------------------------------------
        # Vulnerabilidade #2 (XSS armazenado): MANTIDA DE PROPOSITO.
        #
        # A descricao da tarefa continua sendo inserida direto no HTML, sem
        # escaping. A correcao completa fica para o Modulo 4 (DAST / OWASP
        # Top 10).
        # ---------------------------------------------------------------------
        items += f"""
        <li>
            <b>{row['title']}</b> - {row['description']}
            {'(feita)' if row['done'] else ''}
        </li>
        """

    return f"""
    <h1>Minhas tarefas ({session['username']})</h1>
    <form method="get">
        <input type="text" name="q" placeholder="buscar tarefa">
        <input type="submit" value="Buscar">
    </form>
    <ul>{items}</ul>
    <a href="{url_for('new_task')}">Nova tarefa</a> |
    <a href="{url_for('logout')}">Sair</a>
    """


@app.route("/tasks/new", methods=["GET", "POST"])
def new_task():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        title = request.form["title"]
        description = request.form["description"]
        db = get_db()
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO tasks (user_id, title, description) "
                "VALUES (%s, %s, %s)",
                (session["user_id"], title, description),
            )
        db.commit()
        return redirect(url_for("tasks"))

    return """
    <h1>Nova tarefa</h1>
    <form method="post">
        Titulo: <input type="text" name="title"><br>
        Descricao: <textarea name="description"></textarea><br>
        <input type="submit" value="Salvar">
    </form>
    """


# -----------------------------------------------------------------------------
# Vulnerabilidade #5 (endpoint de debug exposto): MANTIDA DE PROPOSITO.
#
# Este endpoint continua publico e sem autenticacao. A correcao definitiva
# fica para o Modulo 4 (DAST), junto com a correcao do XSS acima.
# -----------------------------------------------------------------------------
@app.route("/debug/info")
def debug_info():
    import platform
    import sys

    return {
        "python_version": sys.version,
        "platform": platform.platform(),
        "secret_key": app.config["SECRET_KEY"],
    }


if __name__ == "__main__":
    with app.app_context():
        init_db()
    # debug=True continua ligado aqui de proposito, no mesmo espirito dos
    # itens acima: sera corrigido junto com o hardening final de
    # configuracao de execucao, discutido em modulos posteriores.
    app.run(host="0.0.0.0", port=5000, debug=True)
