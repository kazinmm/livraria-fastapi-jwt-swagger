# API Livraria - FastAPI

API de exemplo para a atividade de Livros e Autores, com:
- Cadastro e login
- Hash de senhas usando BCrypt
- Token JWT Bearer com expiração
- Perfis ADMIN e USER
- SQLite para persistir usuários, autores, livros e comentários
- OpenAPI e Swagger UI automáticos em `/docs`

## Requisitos
Python 3.10 ou superior.

## Executar no Windows (PowerShell)
Abra o terminal nesta pasta e rode:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
uvicorn main:app --reload
```

Se o PowerShell bloquear a ativação do ambiente virtual, você pode pular a ativação e executar:
```powershell
py -m pip install -r requirements.txt
py -m uvicorn main:app --reload
```

Abra:
- Swagger: http://127.0.0.1:8000/docs
- OpenAPI JSON: http://127.0.0.1:8000/openapi.json

## Usuários iniciais
- ADMIN: `admin@livraria.com` / `admin123`
- USER: `leitor@gmail.com` / `leitor123`

## Testar no Swagger
1. Faça POST `/api/v1/auth/login` com JSON, por exemplo:
   `{"email":"admin@livraria.com","password":"admin123"}`
2. Copie `access_token` da resposta.
3. Clique em **Authorize** no Swagger e cole o token no campo Bearer. Não digite `Bearer ` se o campo solicitar apenas o token.
4. Teste as rotas protegidas.

## Rotas principais
- `POST /api/v1/auth/register` — público; cria USER
- `POST /api/v1/auth/login` — público; retorna JWT
- `GET /api/v1/livros` — público
- `GET /api/v1/livros/{book_id}` — público
- `POST /api/v1/autores` — somente ADMIN
- `POST /api/v1/livros` — somente ADMIN
- `POST /api/v1/livros/{book_id}/comentarios` — USER ou ADMIN
- `GET /api/v1/livros/{book_id}/comentarios` — público
- `GET /api/v1/auth/me` — autenticado

A base de dados `livraria.db` é criada automaticamente ao iniciar a aplicação. A chave JWT padrão é apenas para desenvolvimento acadêmico; defina `JWT_SECRET_KEY` no ambiente para usar outra chave.
