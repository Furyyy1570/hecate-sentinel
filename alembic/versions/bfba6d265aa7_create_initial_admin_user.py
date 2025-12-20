"""create_initial_admin_user

Revision ID: bfba6d265aa7
Revises: 71ef6590f079
Create Date: 2025-12-20 19:26:55.193491

"""

from typing import Sequence, Union
from uuid import uuid4

from alembic import op
from argon2 import PasswordHasher
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "bfba6d265aa7"
down_revision: Union[str, Sequence[str], None] = "71ef6590f079"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Admin user configuration
ADMIN_USERNAME = "admin"
ADMIN_EMAIL = "admin@example.com"
ADMIN_PASSWORD = "admin1234qwer"
ADMIN_GROUP = "site_admins"


def upgrade() -> None:
    """Create initial admin user and site_admins group."""
    # Get connection for raw SQL
    conn = op.get_bind()

    # Hash the password using Argon2 (same settings as src/core/security.py)
    ph = PasswordHasher(
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        salt_len=16,
    )
    hashed_password = ph.hash(ADMIN_PASSWORD)

    # Check if admin user already exists
    result = conn.execute(
        sa.text("SELECT id FROM users WHERE username = :username"),
        {"username": ADMIN_USERNAME},
    )
    existing_user = result.fetchone()

    if existing_user:
        # User already exists, skip
        return

    # Create the site_admins group (if not exists)
    result = conn.execute(
        sa.text("SELECT id FROM groups WHERE name = :name"),
        {"name": ADMIN_GROUP},
    )
    group_row = result.fetchone()

    if group_row:
        group_id = group_row[0]
    else:
        # Insert the group (pub_date and mod_date have defaults)
        conn.execute(
            sa.text(
                """
                INSERT INTO groups (uuid, name, is_active, is_deleted)
                VALUES (:uuid, :name, true, false)
                """
            ),
            {
                "uuid": str(uuid4()),
                "name": ADMIN_GROUP,
            },
        )
        # Get the inserted group id
        result = conn.execute(
            sa.text("SELECT id FROM groups WHERE name = :name"),
            {"name": ADMIN_GROUP},
        )
        group_id = result.fetchone()[0]

    # Create the admin user (pub_date and mod_date have defaults)
    conn.execute(
        sa.text(
            """
            INSERT INTO users (uuid, username, password, is_admin, is_active, is_deleted,
                               token_version, totp_enabled)
            VALUES (:uuid, :username, :password, true, true, false, 0, false)
            """
        ),
        {
            "uuid": str(uuid4()),
            "username": ADMIN_USERNAME,
            "password": hashed_password,
        },
    )

    # Get the inserted user id
    result = conn.execute(
        sa.text("SELECT id FROM users WHERE username = :username"),
        {"username": ADMIN_USERNAME},
    )
    user_id = result.fetchone()[0]

    # Create the admin email (verified) - pub_date and mod_date have defaults
    conn.execute(
        sa.text(
            """
            INSERT INTO emails (uuid, user_id, email_address, is_primary, is_verified,
                                is_active, is_deleted)
            VALUES (:uuid, :user_id, :email, true, true, true, false)
            """
        ),
        {
            "uuid": str(uuid4()),
            "user_id": user_id,
            "email": ADMIN_EMAIL,
        },
    )

    # Link user to site_admins group
    conn.execute(
        sa.text(
            """
            INSERT INTO user_groups (user_id, group_id)
            VALUES (:user_id, :group_id)
            """
        ),
        {
            "user_id": user_id,
            "group_id": group_id,
        },
    )


def downgrade() -> None:
    """Remove initial admin user and site_admins group."""
    conn = op.get_bind()

    # Get user id
    result = conn.execute(
        sa.text("SELECT id FROM users WHERE username = :username"),
        {"username": ADMIN_USERNAME},
    )
    user_row = result.fetchone()

    if user_row:
        user_id = user_row[0]

        # Delete user_groups link
        conn.execute(
            sa.text("DELETE FROM user_groups WHERE user_id = :user_id"),
            {"user_id": user_id},
        )

        # Delete email
        conn.execute(
            sa.text("DELETE FROM emails WHERE user_id = :user_id"),
            {"user_id": user_id},
        )

        # Delete user
        conn.execute(
            sa.text("DELETE FROM users WHERE id = :id"),
            {"id": user_id},
        )

    # Delete group (only if no other users are linked)
    result = conn.execute(
        sa.text("SELECT id FROM groups WHERE name = :name"),
        {"name": ADMIN_GROUP},
    )
    group_row = result.fetchone()

    if group_row:
        group_id = group_row[0]

        # Check if any users are still linked
        result = conn.execute(
            sa.text("SELECT COUNT(*) FROM user_groups WHERE group_id = :group_id"),
            {"group_id": group_id},
        )
        count = result.fetchone()[0]

        if count == 0:
            # No users linked, safe to delete
            conn.execute(
                sa.text("DELETE FROM groups WHERE id = :id"),
                {"id": group_id},
            )
