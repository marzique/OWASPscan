from sqlalchemy import create_engine, inspect
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import exc


def get_passwords(path_to_db_file):
    """Find password field among all tables from SQLite .db file and return list of strings"""

    engine = create_engine(f"sqlite:///{path_to_db_file}", echo=False)
    Base = declarative_base(engine)

    # heuristics
    passfields = ["passwords", "pass", "hash", "passes", "password", "passwd", "password_hash", "user_pass", "pwd"]

    inspector = inspect(engine)
    table = None
    column_name = None
    result = {}
    
    # loop through all tables and find password field
    for table_name in inspector.get_table_names():
        for column in inspector.get_columns(table_name):
            if column['name'] in passfields:
                # print(f"Table {table_name} Column: {column['name']}")
                table = table_name
                result["table"] = table
                column_name = column['name']
                result["column"] = column_name
    
    # go through if column found
    if not column_name:
        return {"error": "No password column found"}

    ########################################################################
    class Users(Base):
        """"""
        __tablename__ = table
        __table_args__ = {'autoload': True}


    Session = sessionmaker(bind=engine)
    session = Session()
    users = session.query(Users).all()
    result["passwords"] = []

    for user in users:
        result["passwords"].append(getattr(user, column_name))
    return result


if __name__ == "__main__":
    print(get_passwords("site.db"))
