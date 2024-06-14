from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Three tables: user_shares stores the amount of shares the user has in a given company
# tickers stores the id of the different companys to buy shares from
# transactions stores users transaction history

db.execute("""
    CREATE TABLE IF NOT EXISTS user_shares (
        id INTEGER PRIMARY KEY,
        usrId INT NOT NULL,
        quoteId INT NOT NULL,
        shares INT NOT NULL
    )
""")

db.execute("""
    CREATE TABLE IF NOT EXISTS tickers (
        id INTEGER PRIMARY KEY,
        ticker VARCHAR(6) UNIQUE NOT NULL
    )
""")

db.execute("""
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY,
        trans_type TEXT,
        quoteId INT NOT NULL,
        share_price NUMBER,
        shares NUMBER,
        usrId INT NOT NULL,
        date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
""")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    usrId = session["user_id"]

    # Cash
    usrCash = db.execute("SELECT cash FROM users WHERE id = ?", usrId)

    # User Shares / Tickers
    # Withouth try-except block, when first booting up, it would end up trying to access tables that didnt exist yet, resulting in error)
    try:
        usrShares = db.execute(
            "SELECT shares, ticker FROM user_shares JOIN tickers ON user_shares.quoteId = tickers.id WHERE usrId = ?", usrId)
    except:
        usrShares = []

    length = len(usrShares)
    for i in range(length):
        # Add quotes to usrShares array
        usrShares[i]['quote'] = None
        quote = lookup(usrShares[i]['ticker'])
        try:
            usrShares[i]['quote'] = quote['price']
        except:
            return apology(f"Error retrieving quote")

    totalAmount = 0
    for item in usrShares:
        totalAmount += item['shares'] * item['quote']

    return render_template("index.html", usrCash=usrCash, usrShares=usrShares, totalAmount=totalAmount)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        quote = lookup(symbol)

        try:
            shares = int(request.form.get("shares"))
        except ValueError:
            return apology("Invalid input: shares number must be a positive integer")

        if symbol is None or shares is None:
            return apology("Must provide symbol and shares")
        elif quote is None:
            return apology("Invalid quote")
        elif shares <= 0:
            return apology("Invalid input: shares number must be a positive integer")

        usrId = session["user_id"]
        usrCash = db.execute("SELECT cash FROM users WHERE id = ?", usrId)
        sharePrice = shares * quote['price']

        print(f"DEBUG: usrId={usrId}, usrCash={usrCash}, sharePrice={sharePrice}")

        if usrCash[0]['cash'] < sharePrice:
            return apology("Insufficient Funds: Please add funds to your account and try again.")

        # We insert new ticker in case it is not in the the ticker table
        tickerExists = db.execute("SELECT ticker FROM tickers WHERE ticker = ? ", quote['symbol'])
        if not tickerExists:
            db.execute("INSERT INTO tickers (ticker) VALUES (?)", quote['symbol'])

        symbolId = db.execute("SELECT id FROM tickers WHERE ticker = ? ", quote['symbol'])
        sharesExists = db.execute("SELECT shares FROM user_shares WHERE usrId = ? and quoteId = ?", usrId, symbolId[0]['id'])

        # If user already bought shares, we update the value. Else we insert data into new row in our user_shares table
        if sharesExists:
            db.execute("UPDATE user_shares SET shares = shares + ? WHERE usrId = ? AND quoteId = ?",
                       shares, usrId, symbolId[0]['id'])
        else:
            db.execute("INSERT INTO user_shares (usrId, quoteId, shares) VALUES (?, ?, ?)", usrId, symbolId[0]['id'], shares)

        # Update users total cash
        db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", sharePrice, usrId)

        # Add transaction data to the transactions table
        trans_type = "Purchase"
        db.execute("INSERT INTO transactions (trans_type, quoteId, share_price, shares, usrId) VALUES (?, ?, ?, ?, ?)",
                   trans_type, symbolId[0]['id'], quote['price'], shares, usrId)

        return redirect("/")

    return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    usrId = session['user_id']
    try:
        transactions = db.execute(
            "SELECT * FROM transactions JOIN tickers ON transactions.quoteId = tickers.id WHERE usrId = ?", usrId)
    except:
        transactions = []

    print(transactions)

    return render_template("history.html", transactions=transactions)


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
        rows = db.execute("SELECT * FROM users WHERE username = ?",
                          request.form.get("username"))

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
    # Did not use extra html page (quoted.html) as check50 would fail to register this extra page and would not validate results
    # Instead, to avoid errors, I set quote = None and in quote.html, I only render the data if quote is not equal to None
    quote = None
    if request.method == "POST":
        symbol = request.form.get("symbol")
        quote = lookup(symbol)

        if not symbol:
            return apology("Must provide quote")
        elif quote is None:
            return apology("Invalid quote")

        quote['price'] = usd(quote['price'])

    return render_template("/quote.html", quote=quote)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        usrExists = db.execute("SELECT * FROM users WHERE username = ?", username)

        if not username or not password:
            return apology("Must provide username and password")
        elif password != confirmation:
            return apology("Password and confirmation fields do not match")
        elif usrExists:
            return apology("Invalid username: already exists!")

        hashPassword = generate_password_hash(password)
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hashPassword)
        usr = db.execute("SELECT * FROM users WHERE username = ?", username)
        session["user_id"] = usr[0]["id"]

        return redirect("/")

    return render_template("/register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    usrId = session["user_id"]
    usrTickers = db.execute(
        "SELECT ticker FROM tickers WHERE id IN (SELECT quoteId FROM user_shares WHERE usrId = ? AND shares > 0)", usrId)

    if request.method == "POST":
        symbol = request.form.get("symbol")
        quote = lookup(symbol)

        try:
            shares = int(request.form.get("shares"))
        except ValueError:
            return apology("Invalid input: shares number must be a positive integer")

        if symbol is None or shares is None:
            return apology("Must provide symbol and shares")
        elif quote is None:
            return apology("Invalid quote")
        elif shares < 0:
            return apology("Invalid input: shares number must be a positive integer")

        usrShares = db.execute(
            "SELECT shares FROM user_shares WHERE usrId = ? AND quoteId = (SELECT id FROM tickers WHERE ticker = ?)", usrId, quote['symbol'])
        # Validate that the user does try to sell shares he does not own or more than he owns
        if not usrShares:
            return apology("Selling shares from a non-owned company")
        elif shares > usrShares[0]['shares']:
            return apology("Trying to sell more shares than you own")

        sharePrice = shares * quote['price']

        db.execute("UPDATE user_shares SET shares = shares - ? WHERE usrId = ? AND quoteId = (SELECT id FROM tickers WHERE ticker = ?) ",
                   shares, usrId, quote['symbol'])
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", sharePrice, usrId)

        # Add transaction data to the transactions table
        trans_type = "Sale"
        symbolId = db.execute("SELECT id FROM tickers WHERE ticker = ?", quote['symbol'])
        db.execute("INSERT INTO transactions (trans_type, quoteId, share_price, shares, usrId) VALUES (?, ?, ?, ?, ?)",
                   trans_type, symbolId[0]['id'], quote['price'], shares, usrId)

        return redirect("/")

    return render_template("/sell.html", usrTickers=usrTickers)


# Change Password
@app.route("/new-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not password:
            return apology("Must provide password")
        elif password != confirmation:
            return apology("Password and confirmation fields do not match")

        hashPassword = generate_password_hash(password)
        usrId = session["user_id"]

        db.execute("UPDATE users SET hash = ? WHERE id = ?", hashPassword, usrId)

        return redirect("/")

    return render_template("new-password.html")
