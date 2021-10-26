from cs50 import SQL

db = SQL("sqlite:///finance.db")

allUsers = db.execute("SELECT cash FROM users WHERE id=2")[0]['cash']
name = "Alex2"



print(allUsers)