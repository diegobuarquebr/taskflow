"""
TaskFlow - versao corrigida para o Modulo 4 (DAST).

Esta versao parte do principio de que as vulnerabilidades de SQL Injection
e SECRET_KEY hardcoded (trabalhadas com SAST no Modulo 3) ja foram
corrigidas. Como este arquivo nao tem acesso direto ao "app_fixed_sast.py"
produzido naquele modulo, essas correcoes sao reaplicadas aqui tambem, para
que o arquivo fique completo, coerente e executavel de forma independente.

Correcoes aplicadas nesta versao (Modulo 4 - DAST):
  1. XSS armazenado CORRIGIDO: toda a renderizacao de HTML foi migrada de
     f-strings manuais para templates Jinja2 (render_template), que aplicam
     escaping automatico (autoescape) em qualquer valor inserido via
     "{{ variavel }}". Ver pasta templates/.
  2. Endpoint "/debug/info" REMOVIDO. Informacoes de diagnostico do
     servidor (versao do Python, plataforma, segredos) nunca devem ser
     expostas publicamente - se for necessario um endpoint de saude/debug,
     ele deve exigir autenticacao de administrador e nunca vazar segredos.
  3. "debug=True" substituido por leitura de variavel de ambiente
     (FLASK_DEBUG), com padrao seguro (False/desligado). Em producao, o
     Werkzeug debugger interativo NUNCA deve estar acessivel.

Correcoes reaplicadas do Modulo 3 (SAST), para manter o arquivo coerente:
  4. SQL Injection CORRIGIDA no login e na busca de tarefas: as queries
     agora usam parametros preparados ("?") em vez de concatenacao de
     string.
  5. SECRET_KEY lido de variavel de ambiente (FLASK_SECRET_KEY), nunca mais
     hardcoded no codigo-fonte.
  6. Bonus de coerencia: senhas armazenadas com hash (werkzeug.security),
     em vez de texto puro, ja que a tabela de usuarios e recriada do zero
     nesta versao. (O Modulo 2/3 tambem cobre esse ponto: se voce esta
     comparando com uma versao anterior que ainda usa texto puro, essa e
     uma diferenca proposital de completude deste arquivo.)

Vulnerabilidades que PERMANECEM de propósito neste modulo (fora de escopo
do Modulo 4, tratadas em modulos futuros ou fora do currículo introdutório):
  - Ausência de rate limiting no login (relacionado a A07 - ver Encontro 9).
  - Ausência de logging estruturado de eventos de seguranca (Modulo 6).
"""

import os
import sqlite3

from flask import Flask, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

# Correcao (Modulo 3): o segredo de sessao agora vem de uma variavel de
# ambiente. Nunca faca commit do valor real - use um gerenciador de
# segredos (Vault, AWS Secrets Manager, GitHub Actions Secrets etc.) em
# ambientes reais. Aqui usamos um fallback apenas para nao quebrar a
# execucao local em ambiente de laboratorio - isso NAO deveria existir em
# producao.
app.config["SECRET_KEY"] = os.environ.get(
    "FLASK_SECRET_KEY", "apenas-para-lab-troque-via-env-var"
)

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
        # Correcao (Modulo 2/3): senha armazenada como hash, nunca em
        # texto puro.
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

        # Correcao (Modulo 3): query parametrizada, sem concatenacao de
        # string. O SQLite (e qualquer outro driver DB-API 2.0) trata o
        # valor do placeholder "?" estritamente como dado, nunca como
        # parte do comando SQL.
        db = get_db()
        cur = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        )
        user = cur.fetchone()

        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("tasks"))
        error = "Usuario ou senha invalidos."

    # Correcao (Modulo 4): renderizacao via template Jinja2 em vez de
    # f-string manual. Qualquer valor passado a "render_template" e
    # escapado automaticamente pelo autoescape do Jinja2 ao ser inserido
    # com "{{ ... }}" no template - inclusive a variavel "error" abaixo,
    # que antes era interpolada crua no HTML.
    return render_template("login.html", error=error)


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
        # Correcao (Modulo 3): busca tambem parametrizada. O padrao LIKE
        # e montado concatenando o "%" ao valor JA PASSADO COMO PARAMETRO,
        # nunca concatenando o valor do usuario direto na string SQL.
        like_pattern = f"%{search}%"
        rows = db.execute(
            "SELECT * FROM tasks WHERE user_id = ? AND title LIKE ?",
            (session["user_id"], like_pattern),
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT * FROM tasks WHERE user_id = ?", (session["user_id"],)
        ).fetchall()

    # Correcao (Modulo 4): a lista de tarefas e passada como dado estruturado
    # (lista de linhas do banco) para o template "tasks.html", que usa
    # "{{ task['title'] }}" / "{{ task['description'] }}" com autoescape.
    # Isso elimina a XSS armazenada: se a descricao contiver
    # "<script>...</script>" ou "<img onerror=...>", o Jinja2 converte os
    # caracteres especiais em entidades HTML (&lt;, &gt; etc.) antes de
    # enviar a resposta, entao o navegador exibe o texto literal em vez de
    # executar o conteudo.
    return render_template(
        "tasks.html", tasks=rows, username=session["username"], search=search
    )


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

    return render_template("new_task.html")


# Correcao (Modulo 4): o endpoint "/debug/info" foi REMOVIDO por completo.
# Informacoes de diagnostico interno do servidor (versao de linguagem,
# plataforma, segredos de configuracao) nunca devem ser expostas via um
# endpoint publico. Se um endpoint de diagnostico for realmente necessario
# (por exemplo, para monitoramento), ele deve:
#   a) exigir autenticacao de administrador (nao apenas login comum);
#   b) nunca retornar segredos (SECRET_KEY, tokens, credenciais de banco);
#   c) idealmente, ficar disponivel apenas em uma rede interna/management,
#      nunca na mesma rota publica da aplicacao.
#
# Exemplo de como um endpoint de "health check" seguro poderia ser
# reintroduzido, caso o time realmente precise de um:
#
# @app.route("/health")
# def health():
#     # Sem informacoes sensiveis - apenas confirma que o processo esta de pe.
#     return {"status": "ok"}


if __name__ == "__main__":
    with app.app_context():
        init_db()

    # Correcao (Modulo 4): "debug" agora vem de uma variavel de ambiente,
    # com padrao DESLIGADO (False). Em producao, FLASK_DEBUG nunca deve
    # ser definida como verdadeira - o Werkzeug debugger interativo, quando
    # habilitado, permite execucao remota de codigo Python por qualquer
    # pessoa que alcance a aplicacao.
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() in (
        "1",
        "true",
        "yes",
    )
    app.run(host="0.0.0.0", port=5000, debug=debug_mode)