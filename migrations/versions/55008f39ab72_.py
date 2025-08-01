"""empty message

Revision ID: 55008f39ab72
Revises: 06acfbd2916d
Create Date: 2025-06-30 10:06:57.632448

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '55008f39ab72'
down_revision = '06acfbd2916d'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('items', schema=None) as batch_op:
        batch_op.add_column(sa.Column('description', sa.String(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('items', schema=None) as batch_op:
        batch_op.drop_column('description')

    # ### end Alembic commands ###
