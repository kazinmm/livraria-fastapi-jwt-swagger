import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field

DB_PATH = os.getenv("LIVRARIA_DB", "livraria.db")
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "troque-esta-chave-por-uma-chave-secreta-longa")
ALGORITHM = "HS256"
TOKEN_MINUTES = 60

app = FastAPI(
    title="API Livraria - Livros e Autores",
    description="API REST com autenticação JWT, permissões por perfil e documentação OpenAPI.",
    version="1.0.0",
    openapi_tags=[
        {"name": "Autenticação", "description": "Cadastro e login de usuários."},
        {"name": "Livros", "description": "Consulta e cadastro de livros."},
        {"name": "Autores", "description": "Cadastro de autores."},
        {"name": "Comentários", "description": "Comentários de leitores nos livros."},
    ],
)
bearer = HTTPBearer(auto_error=False)


def connect():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def init_db():
    with connect() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('ADMIN', 'USER'))
        );
        CREATE TABLE IF NOT EXISTS authors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            biography TEXT
        );
        CREATE TABLE IF NOT EXISTS books (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            year INTEGER,
            author_id INTEGER,
            FOREIGN KEY(author_id) REFERENCES authors(id)
        );
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            book_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            text TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(book_id) REFERENCES books(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """)
        admin = con.execute("SELECT id FROM users WHERE email = ?", ("admin@livraria.com",)).fetchone()
        if not admin:
            con.execute(
                "INSERT INTO users(name, email, password_hash, role) VALUES (?, ?, ?, ?)",
                ("Administrador", "admin@livraria.com", hash_password("admin123"), "ADMIN"),
            )
        user = con.execute("SELECT id FROM users WHERE email = ?", ("leitor@gmail.com",)).fetchone()
        if not user:
            con.execute(
                "INSERT INTO users(name, email, password_hash, role) VALUES (?, ?, ?, ?)",
                ("Leitor", "leitor@gmail.com", hash_password("leitor123"), "USER"),
            )
        if con.execute("SELECT COUNT(*) FROM authors").fetchone()[0] == 0:
            con.execute("INSERT INTO authors(name, biography) VALUES (?, ?)", ("Machado de Assis", "Escritor brasileiro."))
            con.execute("INSERT INTO authors(name, biography) VALUES (?, ?)", ("Clarice Lispector", "Escritora brasileira."))
        if con.execute("SELECT COUNT(*) FROM books").fetchone()[0] == 0:
            a1 = con.execute("SELECT id FROM authors WHERE name = ?", ("Machado de Assis",)).fetchone()["id"]
            a2 = con.execute("SELECT id FROM authors WHERE name = ?", ("Clarice Lispector",)).fetchone()["id"]
            con.execute("INSERT INTO books(title, description, year, author_id) VALUES (?, ?, ?, ?)",
                        ("Dom Casmurro", "Romance de Machado de Assis.", 1899, a1))
            con.execute("INSERT INTO books(title, description, year, author_id) VALUES (?, ?, ?, ?)",
                        ("A Hora da Estrela", "Romance de Clarice Lispector.", 1977, a2))


@app.on_event("startup")
def startup():
    init_db()


class RegisterInput(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(min_length=6, max_length=72)


class LoginInput(BaseModel):
    email: EmailStr
    password: str


class AuthorInput(BaseModel):
    name: str = Field(min_length=2, max_length=150)
    biography: Optional[str] = None


class BookInput(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: Optional[str] = None
    year: Optional[int] = Field(default=None, ge=0, le=2100)
    author_id: Optional[int] = None


class CommentInput(BaseModel):
    text: str = Field(min_length=1, max_length=2000)


def create_token(user: sqlite3.Row) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user["id"]),
        "email": user["email"],
        "role": user["role"],
        "iat": now,
        "exp": now + timedelta(minutes=TOKEN_MINUTES),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Token Bearer obrigatório",
                            headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload.get("sub", ""))
    except (jwt.InvalidTokenError, ValueError, TypeError):
        raise HTTPException(status_code=401, detail="Token inválido ou expirado",
                            headers={"WWW-Authenticate": "Bearer"})
    with connect() as con:
        user = con.execute("SELECT id, name, email, role FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        raise HTTPException(status_code=401, detail="Usuário não encontrado")
    return dict(user)


def admin_user(user=Depends(current_user)):
    if user["role"] != "ADMIN":
        raise HTTPException(status_code=403, detail="Acesso permitido somente para ADMIN")
    return user


@app.get("/", tags=["Informações"])
def home():
    return {"mensagem": "API Livraria funcionando", "docs": "/docs", "openapi": "/openapi.json"}


@app.post("/api/v1/auth/register", status_code=201, tags=["Autenticação"],
          summary="Cadastrar usuário", responses={409: {"description": "E-mail já cadastrado"}})
def register(data: RegisterInput):
    with connect() as con:
        exists = con.execute("SELECT id FROM users WHERE email = ?", (data.email,)).fetchone()
        if exists:
            raise HTTPException(status_code=409, detail="E-mail já cadastrado")
        cur = con.execute(
            "INSERT INTO users(name, email, password_hash, role) VALUES (?, ?, ?, 'USER')",
            (data.name, data.email, hash_password(data.password)),
        )
        return {"id": cur.lastrowid, "name": data.name, "email": data.email, "role": "USER"}


@app.post("/api/v1/auth/login", tags=["Autenticação"], summary="Entrar e receber token JWT",
          responses={401: {"description": "Credenciais inválidas"}})
def login(data: LoginInput):
    with connect() as con:
        user = con.execute("SELECT * FROM users WHERE email = ?", (data.email,)).fetchone()
    if not user or not verify_password(data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="E-mail ou senha inválidos")
    return {
        "access_token": create_token(user),
        "token_type": "bearer",
        "expires_in_minutes": TOKEN_MINUTES,
        "user": {"id": user["id"], "name": user["name"], "email": user["email"], "role": user["role"]},
    }


@app.get("/api/v1/livros", tags=["Livros"], summary="Listar livros (público)")
def list_books():
    with connect() as con:
        rows = con.execute("""
            SELECT b.id, b.title, b.description, b.year, b.author_id, a.name AS author_name
            FROM books b LEFT JOIN authors a ON a.id = b.author_id ORDER BY b.id
        """).fetchall()
    return [dict(row) for row in rows]


@app.get("/api/v1/livros/{book_id}", tags=["Livros"], summary="Buscar livro por ID (público)",
         responses={404: {"description": "Livro não encontrado"}})
def get_book(book_id: int):
    with connect() as con:
        row = con.execute("""
            SELECT b.id, b.title, b.description, b.year, b.author_id, a.name AS author_name
            FROM books b LEFT JOIN authors a ON a.id = b.author_id WHERE b.id = ?
        """, (book_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Livro não encontrado")
    return dict(row)


@app.post("/api/v1/autores", status_code=201, tags=["Autores"], summary="Cadastrar autor (ADMIN)",
          responses={401: {"description": "Não autenticado"}, 403: {"description": "Sem permissão"}})
def create_author(data: AuthorInput, user=Depends(admin_user)):
    with connect() as con:
        cur = con.execute("INSERT INTO authors(name, biography) VALUES (?, ?)", (data.name, data.biography))
        return {"id": cur.lastrowid, "name": data.name, "biography": data.biography}


@app.post("/api/v1/livros", status_code=201, tags=["Livros"], summary="Cadastrar livro (ADMIN)",
          responses={401: {"description": "Não autenticado"}, 403: {"description": "Sem permissão"},
                     404: {"description": "Autor não encontrado"}})
def create_book(data: BookInput, user=Depends(admin_user)):
    with connect() as con:
        if data.author_id is not None:
            author = con.execute("SELECT id FROM authors WHERE id = ?", (data.author_id,)).fetchone()
            if not author:
                raise HTTPException(status_code=404, detail="Autor não encontrado")
        cur = con.execute(
            "INSERT INTO books(title, description, year, author_id) VALUES (?, ?, ?, ?)",
            (data.title, data.description, data.year, data.author_id),
        )
        return {"id": cur.lastrowid, **data.model_dump()}


@app.post("/api/v1/livros/{book_id}/comentarios", status_code=201, tags=["Comentários"],
          summary="Comentar em um livro (USER ou ADMIN)",
          responses={401: {"description": "Não autenticado"}, 404: {"description": "Livro não encontrado"}})
def create_comment(book_id: int, data: CommentInput, user=Depends(current_user)):
    with connect() as con:
        book = con.execute("SELECT id FROM books WHERE id = ?", (book_id,)).fetchone()
        if not book:
            raise HTTPException(status_code=404, detail="Livro não encontrado")
        cur = con.execute(
            "INSERT INTO comments(book_id, user_id, text, created_at) VALUES (?, ?, ?, ?)",
            (book_id, user["id"], data.text, datetime.now(timezone.utc).isoformat()),
        )
        return {"id": cur.lastrowid, "book_id": book_id, "user_id": user["id"],
                "user_name": user["name"], "text": data.text}


@app.get("/api/v1/livros/{book_id}/comentarios", tags=["Comentários"],
         summary="Listar comentários de um livro")
def list_comments(book_id: int):
    with connect() as con:
        book = con.execute("SELECT id FROM books WHERE id = ?", (book_id,)).fetchone()
        if not book:
            raise HTTPException(status_code=404, detail="Livro não encontrado")
        rows = con.execute("""
            SELECT c.id, c.book_id, c.user_id, u.name AS user_name, c.text, c.created_at
            FROM comments c JOIN users u ON u.id = c.user_id
            WHERE c.book_id = ? ORDER BY c.id
        """, (book_id,)).fetchall()
    return [dict(row) for row in rows]


@app.get("/api/v1/auth/me", tags=["Autenticação"], summary="Ver usuário autenticado")
def me(user=Depends(current_user)):
    return user
