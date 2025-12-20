"""add uuid to all models

Revision ID: 71ef6590f079
Revises: be22f3475423
Create Date: 2025-12-20 14:06:09.961383

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '71ef6590f079'
down_revision: Union[str, Sequence[str], None] = 'be22f3475423'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Tables that need UUID column added
TABLES = [
    'email_verification_tokens',
    'emails',
    'groups',
    'oauth_accounts',
    'oauth_states',
    'password_reset_tokens',
    'permissions',
    'phones',
    'recovery_codes',
    'totp_pending_auth',
]


def upgrade() -> None:
    """Upgrade schema."""
    for table in TABLES:
        # Add column as nullable first
        op.add_column(table, sa.Column('uuid', sa.UUID(), nullable=True))

        # Generate UUIDs for existing rows
        op.execute(f"UPDATE {table} SET uuid = gen_random_uuid() WHERE uuid IS NULL")

        # Make column non-nullable
        op.alter_column(table, 'uuid', nullable=False)

        # Add unique index
        op.create_index(op.f(f'ix_{table}_uuid'), table, ['uuid'], unique=True)


def downgrade() -> None:
    """Downgrade schema."""
    for table in TABLES:
        op.drop_index(op.f(f'ix_{table}_uuid'), table_name=table)
        op.drop_column(table, 'uuid')
