"""Add visitor management tables

Revision ID: c36b5bd18601
Revises: c2488eaf3392
Create Date: 2025-11-05 12:33:04.217362

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c36b5bd18601'
down_revision: Union[str, None] = 'c2488eaf3392'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Tables and columns already exist from manual creation
    pass


def downgrade() -> None:
    # No operation needed for downgrade
    pass
