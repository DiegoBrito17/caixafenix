"""Reset admin password using application context.
Usage:
  Set environment variable NEW_ADMIN_PASSWORD and run: python scripts/reset_admin_password.py
This connects to the existing database configured by the app and updates the 'admin' user.
"""
import os
from werkzeug.security import generate_password_hash

from app import app, db, Usuario

new_pass = os.environ.get('NEW_ADMIN_PASSWORD')
if not new_pass:
    print('ERROR: Set NEW_ADMIN_PASSWORD environment variable.')
    raise SystemExit(1)

with app.app_context():
    user = Usuario.query.filter_by(nome='admin').first()
    if not user:
        print('No user named "admin" found.')
        raise SystemExit(1)
    user.senha = generate_password_hash(new_pass)
    db.session.commit()
    print('Admin password updated successfully (password not printed).')
