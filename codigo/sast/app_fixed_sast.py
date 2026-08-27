"""
TaskFlow - Versao CORRIGIDA apos o Modulo 3 (SAST + Secret Scanning).

Este arquivo e o resultado do laboratorio do Encontro 6. A partir da versao
vulneravel original (app-exemplo/app.py), corrigimos APENAS as
vulnerabilidades de CODIGO que um SAST (Semgrep) e um secret scanner
(Gitleaks) sabem detectar:

  1. SQL Injection no login          -> CORRIGIDO (query parametrizada)
  2. XSS armazenado na descricao      -> AINDA PRESENTE DE PROPOSITO
  3. SECRET_KEY hardcoded             -> CORRIGIDO (variavel de ambiente)
  4. Senha em texto puro              -> CORRIGIDO (hash com Werkzeug)
  5. Endpoint /debug/info exposto     -> AINDA PRESENTE DE PROPOSITO
  6. Dependencias com CVEs            -> tratado a parte no Encontro 7 (SCA),
                                          ver codigo/requirements-fixed.txt

Os itens 2 e 5 (XSS e /debug/info exposto) sao mantidos INTACTOS de
proposito nesta versao. Eles fogem do escopo de SAST/SCA e serao o alvo
do Modulo 4 (DAST e OWASP Top 10), quando os alunos vao descobri-los com
a aplicacao rodando (dynamic testing) em vez de lendo o codigo-fonte.
Nao "adiante" a correcao deles aqui - isso e intencional no plano de aula.
"""

import os
import sqlite3

from flask import Flask, g, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

# -----------------------------------------------------------------------
# CORRECAO da Vulnerabilidade #3: SECRET_KEY hardcoded.
#
# Antes:
#   app.config["SECRET_KEY"] = "s3gr3d0-super-secreto-nao-mude-nunca"
#
# Depois: o valor vem de uma variavel de ambiente (nunca commitada no
# repositorio). Se a variavel nao existir, a aplicacao falha explicitamente
# na inicializacao em vez de "cair para trás" silenciosamente em um valor
# fixo - um fallback silencioso reintroduziria o mesmo problema.
#
# Como configurar localmente:
#   export TASKFLOW_SECRET_KEY="um-valor-aleatorio-e-longo-gerado-por-voce"
#
# Em producao, este valor deveria vir de um cofre de segredos (ex: GitHub
# Actions Secrets, AWS Secrets Manager, HashiCorp Vault) - assunto que
# volta a aparecer nos modulos seguintes.
# -----------------------------------------------------------------------
app = Flask(__name__)

_secret_key = os.environ.get("TASKFLOW_SECRET_KEY")
if not _secret_key:
    raise RuntimeError(
        "Variavel de ambiente TASKFLOW_SECRET_KEY nao foi definida. "
        "Configure-a antes de iniciar a aplicacao "
        "(ex: export TASKFLOW_SECRET_KEY='valor-aleatorio-e-longo')."
    )
app.config["SECRET_KEY"] = _secret_key

DATABASE = "taskflow.db"


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            done INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
        """
    )
    db.commit()

    cur = db.execute("SELECT COUNT(*) AS total FROM users")
    if cur.fetchone()["total"] == 0:
        # -----------------------------------------------------------
        # CORRECAO da Vulnerabilidade #4: senha em texto puro.
        #
        # Antes: db.execute(..., ("admin", "admin123"))
        #
        # Depois: usamos generate_password_hash() do proprio Werkzeug
        # (dependencia que o Flask ja traz) para armazenar apenas o HASH
        # da senha, nunca a senha em si. generate_password_hash() ja
        # cuida de aplicar "salt" automaticamente, entao dois usuarios
        # com a mesma senha geram hashes diferentes no banco.
        # -----------------------------------------------------------
        db.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            ("admin", generate_password_hash("admin123")),
        )
        db.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
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

        # -----------------------------------------------------------
        # CORRECAO da Vulnerabilidade #1: SQL Injection no login.
        #
        # Antes: a query era montada por concatenacao de string,
        # permitindo que um atacante enviasse, por exemplo,
        #   username = admin' --
        # para comentar o restante da query e autenticar sem senha.
        #
        # Depois: usamos uma query PARAMETRIZADA com placeholders "?".
        # O driver sqlite3 trata os valores de "username" e "password"
        # sempre como DADOS, nunca como parte do comando SQL - eles nao
        # podem "escapar" da query e alterar sua estrutura, nao importa
        # o que o usuario digite. Este e o mesmo padrao ja usado em
        # get_db()/init_db() e no INSERT de new_task() no arquivo
        # original: siga sempre esse exemplo.
        # -----------------------------------------------------------
        db = get_db()
        cur = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        )
        user = cur.fetchone()

        # -----------------------------------------------------------
        # Ajuste necessario por causa da correcao da Vulnerabilidade #4:
        # agora que a senha esta armazenada como hash, nao podemos mais
        # comparar "password == user['password']" diretamente. Usamos
        # check_password_hash(), que recalcula o hash da senha recebida
        # com o mesmo salt e compara com o hash salvo no banco.
        # -----------------------------------------------------------
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

    if search:
        # -----------------------------------------------------------
        # CORRECAO da Vulnerabilidade #1 (variante): SQL Injection na
        # busca de tarefas.
        #
        # Antes: "... AND title LIKE '%" + search + "%'" concatenado.
        #
        # Depois: o padrao de LIKE tambem pode (e deve) ser passado como
        # parametro. Montamos a string "%termo%" em Python e a enviamos
        # inteira como um UNICO parametro "?" - o SQLite nunca interpreta
        # o conteudo de "search" como parte do comando SQL.
        # -----------------------------------------------------------
        like_pattern = f"%{search}%"
        rows = db.execute(
            "SELECT * FROM tasks WHERE user_id = ? AND title LIKE ?",
            (session["user_id"], like_pattern),
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT * FROM tasks WHERE user_id = ?", (session["user_id"],)
        ).fetchall()

    items = ""
    for row in rows:
        # -----------------------------------------------------------
        # Vulnerabilidade #2 (XSS armazenado): MANTIDA DE PROPOSITO.
        #
        # A descricao da tarefa continua sendo inserida direto no HTML
        # sem nenhum escaping. Um SAST como o Semgrep ja consegue
        # sinalizar isso (regra de "unescaped template" / "XSS"), mas a
        # correcao completa - e a discussao sobre por que isso importa
        # na pratica - fica para o Modulo 4 (DAST / OWASP Top 10), onde
        # os alunos vao explorar essa falha com a aplicacao rodando.
        # -----------------------------------------------------------
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
        db.execute(
            "INSERT INTO tasks (user_id, title, description) VALUES (?, ?, ?)",
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


# -----------------------------------------------------------------------
# Vulnerabilidade #5 (endpoint de debug exposto): MANTIDA DE PROPOSITO.
#
# Este endpoint continua publico e sem autenticacao. SAST estatico as
# vezes acerta esse tipo de problema (ex: regra "debug endpoint exposed"),
# mas o jeito mais didatico de descobrir e explorar isso e testando a
# aplicacao rodando de fato - por isso a correcao definitiva fica para o
# Modulo 4 (DAST), junto com a correcao do XSS acima.
# -----------------------------------------------------------------------
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