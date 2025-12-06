from sqlalchemy import create_engine, String
from sqlalchemy.orm import Mapped, mapped_column, declarative_base, sessionmaker
import os
from dotenv import load_dotenv
from pydantic import EmailStr
import bcrypt

load_dotenv()

DB_URL = os.getenv('DB_URL')

engine = create_engine(DB_URL)

Base = declarative_base()

Session = sessionmaker(bind=engine)

class User(Base):
    __tablename__ = 'users'
    
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(50))
    password: Mapped[str] = mapped_column()
    email: Mapped[str] = mapped_column(unique=True)
    
    def set_password(self, password: str):
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def check_password(self, password: str):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))
    
def get_db():
    db = Session()
    try:
        yield db
    finally:
        db.close()
        
Base.metadata.create_all(bind=engine)