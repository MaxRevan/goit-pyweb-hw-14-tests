"""Added Roles

Revision ID: e1ac5cf8bf94
Revises: 3d547cbb1c41
Create Date: 2024-11-17 10:45:38.372233

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from src.auth.models import Role
from src.auth.schema import RoleEnum


# revision identifiers, used by Alembic.
revision: str = 'e1ac5cf8bf94'
down_revision: Union[str, None] = '3d547cbb1c41'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('roles',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_index(op.f('ix_roles_id'), 'roles', ['id'], unique=False)
    # ### end Alembic commands ###

    op.bulk_insert(
        Role.__table__,
        [
            {"id": 1, "name": RoleEnum.ADMIN.value},
            {"id": 2, "name": RoleEnum.USER.value}
        ]
    )


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_roles_id'), table_name='roles')
    op.drop_table('roles')
    # ### end Alembic commands ###
