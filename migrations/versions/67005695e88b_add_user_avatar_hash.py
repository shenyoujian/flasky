"""add User.avatar_hash

Revision ID: 67005695e88b
Revises: 519508ba06b6
Create Date: 2018-04-18 12:44:49.889210

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '67005695e88b'
down_revision = '519508ba06b6'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('avatar_hash', sa.String(length=32), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('users', 'avatar_hash')
    # ### end Alembic commands ###
