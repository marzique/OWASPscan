from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# SQLite


engine = create_engine('sqlite:///site.db', echo=False)
Base = declarative_base(engine)
########################################################################
class Users(Base):
    """"""
    __tablename__ = 'user'
    __table_args__ = {'autoload':True}

#----------------------------------------------------------------------
def loadSession():
    """"""
    metadata = Base.metadata
    Session = sessionmaker(bind=engine)
    session = Session()
    return session

if __name__ == "__main__":
    session = loadSession()
    users = session.query(Users).all()
    for user in users:
        print(user.password)
