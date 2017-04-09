"""Adds oauth tables

Revision ID: 868bb5751da
Revises: 780b1dabd51
Create Date: 2017-02-09 01:50:33.546883

"""

# revision identifiers, used by Alembic.
revision = '868bb5751da'
down_revision = '780b1dabd51'

from alembic import op
from sqlalchemy.sql import text
import sqlalchemy as sa


def upgrade():
    conn = op.get_bind()
    op.create_table('oauthclient', sa.Column('id', sa.BigInteger, primary_key=True), sa.Column('created_at', sa.DateTime, server_default=sa.func.now(), nullable=False), sa.Column('client_id', sa.String(255), nullable=False), sa.Column('client_secret', sa.String(255), nullable=True), sa.Column('name', sa.String(255), nullable=False))
    op.create_table('oauthgrant', sa.Column('id', sa.BigInteger, primary_key=True), sa.Column('created_at', sa.DateTime, server_default=sa.func.now(), nullable=False), sa.Column('grant_code', sa.String(255), nullable=False), sa.Column('account_id', sa.BigInteger, nullable=False), sa.Column('client_id', sa.BigInteger, nullable=False), sa.Column('expires_in', sa.Interval, nullable=False))
    op.create_table('oauthbearertoken', sa.Column('id', sa.BigInteger, primary_key=True), sa.Column('created_at', sa.DateTime, server_default=sa.func.now(), nullable=False), sa.Column('access_token', sa.String(255), nullable=False), sa.Column('namespace_id', sa.BigInteger, nullable=False), sa.Column('client_id', sa.BigInteger, nullable=False))
    op.create_foreign_key('oauthgrant_account_fk', 'oauthgrant', 'account', ['account_id'], ['id'], ondelete='cascade')
    op.create_foreign_key('oauthgrant_client_fk', 'oauthgrant', 'oauthclient', ['client_id'], ['id'], ondelete='cascade')
    op.create_foreign_key('oauthbearertoken_namespace_fk', 'oauthbearertoken', 'namespace', ['namespace_id'], ['id'], ondelete='cascade')
    op.create_foreign_key('oauthbearertoken_client_fk', 'oauthbearertoken', 'oauthclient', ['client_id'], ['id'], ondelete='cascade')


def downgrade():
    conn = op.get_bind()
    op.drop_table('oauthgrant')
    op.drop_table('oauthbearertoken')
    op.drop_table('oauthclient')
