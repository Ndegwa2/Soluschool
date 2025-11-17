"""Add visitor_pass_id column to logs table

Revision ID: add_visitor_pass_id
Revises: c36b5bd18601
Create Date: 2025-11-05 14:53:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'add_visitor_pass_id'
down_revision: Union[str, None] = 'c36b5bd18601'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add visitor_pass_id column to logs table
    op.add_column('logs', sa.Column('visitor_pass_id', sa.Integer(), sa.ForeignKey('visitor_passes.id'), nullable=True))


def downgrade() -> None:
    # Remove visitor_pass_id column from logs table
    op.drop_column('logs', 'visitor_pass_id')