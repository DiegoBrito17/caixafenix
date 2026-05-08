import os
from sqlalchemy import create_engine, MetaData, Table, select, text

# Config
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_env_sqlite_path = os.environ.get('SQLITE_PATH')
_sqlite_candidates = [
    _env_sqlite_path,
    os.path.join(BASE_DIR, 'database', 'caixa.db'),
    os.path.join(BASE_DIR, 'caixa_completo.db'),
]
SQLITE_PATH = next((p for p in _sqlite_candidates if p and os.path.exists(p)), None)
DATABASE_URL = os.environ.get('DATABASE_URL')
RUN_MIGRATION = os.environ.get('RUN_MIGRATION', '0') == '1'

if not DATABASE_URL:
    raise SystemExit("DATABASE_URL não configurada. Ex: postgres://user:pass@host:5432/db")

if DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

SQLITE_URL = f"sqlite:///{SQLITE_PATH}" if SQLITE_PATH else None

TABLE_ORDER = [
    'usuario',
    'caixa',
    'forma_pagamento',
    'bandeira_cartao',
    'categoria_despesa',
    'motoboy',
    'produto',
    'venda',
    'pagamento_venda',
    'delivery',
    'pagamento_delivery',
    'despesa',
    'sangria',
    'suprimento',
    'movimentacao_estoque',
    'licenca',
    'dispositivo',
    'backup',
]


def main():
    if not RUN_MIGRATION:
        print("Migração ignorada (RUN_MIGRATION != 1).")
        return

    if not SQLITE_PATH:
        tried = [p for p in _sqlite_candidates if p]
        if tried:
            print(f"SQLite não encontrado. Caminhos tentados: {', '.join(tried)}. Migração ignorada.")
        else:
            print("SQLite não encontrado (SQLITE_PATH não definido). Migração ignorada.")
        return

    src_engine = create_engine(SQLITE_URL)
    dst_engine = create_engine(DATABASE_URL)

    # Criar tabelas no destino via app models
    from app import app, db  # noqa
    with app.app_context():
        db.create_all()

    src_meta = MetaData()
    dst_meta = MetaData()

    src_meta.reflect(bind=src_engine)
    dst_meta.reflect(bind=dst_engine)

    with dst_engine.begin() as dst_conn:
        # Limpar destino (ordem reversa para respeitar FKs)
        for name in reversed(TABLE_ORDER):
            if name in dst_meta.tables:
                dst_conn.execute(text(f'DELETE FROM {name}'))

        # Copiar dados
        for name in TABLE_ORDER:
            if name not in src_meta.tables or name not in dst_meta.tables:
                continue
            src_table = Table(name, src_meta, autoload_with=src_engine)
            dst_table = Table(name, dst_meta, autoload_with=dst_engine)

            rows = list(src_engine.connect().execute(select(src_table)).mappings())
            if rows:
                dst_conn.execute(dst_table.insert(), rows)
                print(f'OK: {name} ({len(rows)})')
            else:
                print(f'OK: {name} (0)')

    print('Migração concluída.')


if __name__ == '__main__':
    main()
