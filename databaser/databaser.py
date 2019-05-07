from sqlalchemy import create_engine, inspect
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import exc


def get_passwords(path_to_db_file):
    # pass .db filename
    engine = create_engine(f"sqlite:///{path_to_db_file}", echo=False)
    Base = declarative_base(engine)

    passfields = ["passwords", "pass", "hash", "passes", "password", "passwd", "password_hash", "user_pass", "pwd"]

    inspector = inspect(engine)

    table = None
    column_name = None
    
    for table_name in inspector.get_table_names():
        for column in inspector.get_columns(table_name):
            if column['name'] in passfields:
                print(f"Table {table_name} Column: {column['name']}")
                table = table_name
                column_name = column['name']

    ########################################################################
    class Users(Base):
        """"""
        __tablename__ = table
        __table_args__ = {'autoload': True}


    metadata = Base.metadata
    Session = sessionmaker(bind=engine)
    session = Session()
    users = session.query(Users).all()
    passwords = []

    for user in users:
        passwords.append(getattr(user, column_name))
    return passwords


print(get_passwords("site.db"))