"""empty message

Revision ID: 87596a984a70
Revises: 
Create Date: 2024-02-15 16:51:09.042264

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '87596a984a70'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=50), nullable=False),
    sa.Column('password', sa.String(length=100), nullable=False),
    sa.Column('password_hash', sa.String(length=100), nullable=True),
    sa.Column('privacy_setting', sa.String(length=20), nullable=True),
    sa.Column('theme', sa.String(length=20), nullable=True),
    sa.Column('language', sa.String(length=10), nullable=True),
    sa.Column('bio', sa.String(length=255), nullable=True),
    sa.Column('profile_pic', sa.String(length=255), nullable=True),
    sa.Column('email', sa.String(length=120), nullable=False),
    sa.Column('reset_token', sa.String(length=100), nullable=True),
    sa.Column('is_author', sa.Boolean(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email'),
    sa.UniqueConstraint('username')
    )
    op.create_table('follow',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('follower_id', sa.Integer(), nullable=False),
    sa.Column('followed_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['followed_id'], ['user.id'], ),
    sa.ForeignKeyConstraint(['follower_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('notification',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('content', sa.String(length=200), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('timestamp', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('story',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('title', sa.String(length=255), nullable=False),
    sa.Column('synopsis', sa.String(length=1000), nullable=False),
    sa.Column('content', sa.Text(), nullable=False),
    sa.Column('tags', sa.String(length=255), nullable=True),
    sa.Column('author_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['author_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('comment',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('content', sa.Text(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('story_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['story_id'], ['story.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('edit_proposal',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('content', sa.Text(), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('story_id', sa.Integer(), nullable=False),
    sa.Column('timestamp', sa.DateTime(), nullable=True),
    sa.Column('author_approval', sa.Boolean(), nullable=True),
    sa.ForeignKeyConstraint(['story_id'], ['story.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('version',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('date', sa.DateTime(), nullable=False),
    sa.Column('content', sa.Text(), nullable=False),
    sa.Column('story_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['story_id'], ['story.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('version')
    op.drop_table('edit_proposal')
    op.drop_table('comment')
    op.drop_table('story')
    op.drop_table('notification')
    op.drop_table('follow')
    op.drop_table('user')
    # ### end Alembic commands ###
