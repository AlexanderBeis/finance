import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    money = db.execute("SELECT cash FROM users WHERE id=?", session['user_id'])[0]['cash']
    transactions = db.execute("SELECT name, symbol, shares, price FROM transactions WHERE user_id=?", session['user_id'])
    total = 0
    actualTransactions = []
    # show informations
    for c in transactions:
        actualInfo = lookup(c['symbol'])
        actualInfo['shares'] = c['shares']
        actualTransactions.append(actualInfo)
        total = total + actualInfo['price']*c['shares']
    total = total + money

    return render_template("index.html", money=money, trans=actualTransactions, total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == 'POST':
        symbol = request.form['symbol']
        if not symbol:
            return apology('must provide symbol')
        stock = lookup(symbol)
        if stock == None:
            return apology('Invalid Symbol')
        if symbol.upper() not in stock['symbol']:
            return apology('Invalid Symbol')
        try:
            shares = int(request.form['shares'])
        except ValueError:
            return apology('shares must be a integer number')
        if not shares:
            return apology('must provide shares number')
        if shares < 1:
            return apology('shares must be a positive number')

        if not float(request.form['shares']).is_integer():
            return apology('shares must be a integer number')

        if not request.form['shares'].isdigit():
            return apology('shares must be a integer number')
        # show informations
        price = stock['price']
        money = float(db.execute("SELECT cash FROM users WHERE id=?", session['user_id'])[0]['cash'])
        totalPrice = price*shares

        if money < totalPrice:
            return apology(f'you need {totalPrice} to make the transaction, you only have {money}')

        finalMoney = money - totalPrice

        db.execute("UPDATE users SET cash=? WHERE id=?", finalMoney, session['user_id'])

        transactions = db.execute('SELECT symbol, shares FROM transactions WHERE user_id = ?', session['user_id'])

        allSymbols = []
        for c in transactions:
            allSymbols.append(c['symbol'])

        if symbol.upper() in allSymbols:
            indexSymbol = allSymbols.index(symbol.upper())
            finalShares = shares + transactions[indexSymbol]['shares']
            db.execute('UPDATE transactions SET shares=?, price=? WHERE symbol=? AND user_id=?',
                       finalShares, price, symbol.upper(), session['user_id'])
        else:
            db.execute("INSERT INTO transactions (user_id, name, symbol, shares, price) VALUES(?, ?, ?, ?, ?)",
                       session['user_id'], stock['name'], symbol.upper(), shares, price)
        db.execute("INSERT INTO history (user_id, symbol, shares, price) VALUES(?, ?, ?, ?)",
                   session['user_id'], symbol.upper(), shares, price)

        return redirect('/')
    else:
        return render_template('buy.html')


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    history = db.execute('SELECT * FROM history')
    return render_template('history.html', hist=history)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == 'POST':
        symbol = request.form['symbol']

        if not symbol:
            return apology("must provide symbol")
        else:
            stock = lookup(symbol.upper())
            if stock == None:
                return apology("Invalid Symbol")
            return render_template("quoted.html", stockName={'name': stock['name'], 'price': usd(stock['price']), 'symbol': stock['symbol']} )
    else:

        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form['username']
        password = request.form['password']
        confirmation = request.form['confirmation']

        allUsers = db.execute("SELECT username FROM users")
        listUsers = []

        if not username:
            return apology("must provide username")

        for c in allUsers:
            listUsers.append(c['username'])

        if username in listUsers:
            return apology("Username have already been used")

        if not password:
            return apology("must provide password")

        if not confirmation:
            return apology("must provide confirmation")

        if password != confirmation:
            return apology("confirmation should be equal to password")

        hashedPassword = generate_password_hash(password)

        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, hashedPassword)
        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    transactions = db.execute('SELECT symbol, shares, price FROM transactions WHERE user_id = ?', session['user_id'])
    allSymbols = []
    for c in transactions:
        allSymbols.append(c['symbol'])

    if request.method == 'POST':
        symbol = request.form['symbol'].upper()
        stock = lookup(symbol)
        shares = int(request.form['shares'])

        money = db.execute('SELECT cash FROM users WHERE id=?', session['user_id'])[0]['cash']
        if not symbol:
            return apology('must provide a symbol')
        if stock == None:
            return apology('Invalid Symbol')
        if not shares:
            return apology('must provide a share number')

        if symbol not in allSymbols:
            return apology(f'you dont have any share of {symbol}')

        indexSymbol = allSymbols.index(symbol)

        myShares = transactions[indexSymbol]['shares']

        if shares > myShares:
            return apology(f"You don't have enough share to make this transaction")

        finalShares = myShares - shares
        finalMoney = money + shares*stock['price']

        if finalShares == 0:
            db.execute('DELETE FROM transactions WHERE symbol = ? AND user_id=?', symbol, session['user_id'])
        else:
            db.execute('UPDATE transactions SET shares=? WHERE symbol=? AND user_id=?', finalShares, symbol, session['user_id'])
        db.execute("INSERT INTO history (user_id, symbol, shares, price) VALUES(?, ?, ?, ?)", 
                   session['user_id'], symbol.upper(), shares*-1, stock['price'])
        db.execute('UPDATE users SET cash=? WHERE id=?', finalMoney, session['user_id'])
        return redirect('/')
    else:
        return render_template('sell.html', symbols=allSymbols)
        

@app.route("/deposit", methods=["GET", "POST"])
@login_required
def deposit():
    """ Deposit more money """
    money = db.execute('SELECT cash FROM users WHERE id=?', session['user_id'])[0]['cash']
    if request.method == 'POST':
        cash = float(request.form['cash'])
        finalCash = money+cash
        db.execute('UPDATE users SET cash=? WHERE id=?', finalCash, session['user_id'])
        return redirect('/')
    else:
        return render_template('deposit.html', money=money)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
