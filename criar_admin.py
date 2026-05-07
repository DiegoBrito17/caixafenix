if __name__ == "__main__":
    from app import app, db, Usuario
    from werkzeug.security import generate_password_hash

    import getpass
    import os
    import secrets

    with app.app_context():
        nome = (os.environ.get("ADMIN_USERNAME") or "admin").strip()
        senha = (os.environ.get("ADMIN_PASSWORD") or "").strip()

        if not senha:
            try:
                senha = getpass.getpass(f"Defina a senha para o usuário '{nome}': ").strip()
            except Exception:
                senha = ""

        if not senha:
            senha = secrets.token_urlsafe(12)
            print("⚠️  ADMIN_PASSWORD não definido e não foi possível ler do terminal.")
            print(f"🔐 Senha temporária gerada (altere depois no painel): {senha}")

        usuario = Usuario.query.filter_by(nome=nome).first()

        if usuario:
            print("⚠️ Admin já existe")
        else:
            admin = Usuario(
                nome=nome,
                senha=generate_password_hash(senha),
                perfil="ADMIN",
                ativo=True,
                acesso_configuracoes=True,
            )
            db.session.add(admin)
            db.session.commit()
            print("✅ Usuário ADMIN criado com sucesso")
