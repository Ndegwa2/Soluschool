"""add qr_image column

Revision ID: c2488eaf3392
Revises: adfd66ea9105
Create Date: 2025-10-08 14:57:47.564626

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c2488eaf3392'
down_revision: Union[str, None] = 'adfd66ea9105'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
