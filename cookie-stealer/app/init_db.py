import os
import sqlite3
from passlib.hash import bcrypt

DB_PATH = "data.db"

if os.path.exists(DB_PATH):
    os.unlink(DB_PATH)

con = sqlite3.connect(DB_PATH)
cur = con.cursor()
cur.execute(
    "create table users (" + \
    "username varchar(100) primary key, " + \
    "pw_hash varchar(100)" + \
    ")"
)
cur.execute(
    "create table tickets (" + \
    "id integer primary key autoincrement, " + \
    "text text" + \
    ")"
)

admin_pw_hash = bcrypt.hash(os.environ["ADMIN_PW"])
cur.execute(f"insert into users values (\'admin\', \'{admin_pw_hash}\')")
con.commit()
