# cookie-stealer | Web Exploitation | UtahSec 2025-MM-DD

Author: Carson He (zakstamaj)

CTF technical skills workshop on XSS to steal a cookie.

Challenge website: 

## Initial analysis

Take a bit of time to explore the website and the code inside the [app](app) folder. Don't worry if you don't understand the code; this guide will explain the important bits of the code.

The web application is written in Python using the Flask web framework.

### Login

Notice that there is a login page. However, looking through [main.py](app/main.py), there are `/login` and `/logout` routes, but no route for registering a new account. In [init_db.py](app/init_db.py), we see that there is an admin account with a random password generated in [init.sh](app/init.sh), but the password is not visible to us.

### Admin panel and session cookie

In [main.py](app/main.py), we see that there is a route for `/admin` contains the flag.

```py
@app.get("/admin")
def admin():
    if session.get("user") != "admin":
        abort(401)
    return render_template("admin.html", flag=flag)
```

The corresponding `admin.html` template at [templates/admin.html](app/templates/admin.html) shows that the flag is indeed displayed.

```
<p>flag: <code>{{flag}}</code></p>
```

Notice that the `/admin` route checks whether the client is an admin using the Flask session. Also note that Flask sessions are implemented with cookies (<https://flask.palletsprojects.com/en/stable/quickstart/#sessions>). This suggests that if we can steal a valid admin session cookie, then we would be able to access the admin panel and get the flag.

> [!NOTE]
> Flask session cookies contain Base64 encoded JSON data for the claims. Why can't we just make our own session cookie with `{"user":"admin"}`?
>
> Flask session cookies are cryptographically signed with the Flask application's secret key. You can see that the Flask secret key is set in [main.py](app/main.py):
>
> ```
> app.secret_key = os.environ["FLASK_SECRET_KEY"]
> ```
>
> This means that any cookie that we forge will be considered invalid by the Flask application, because we cannot generate a valid signature, because we don't know the correct secret key. We also don't have access to the secret key, since it is randomly generated in [init.sh](app/init.sh).

### Ticket system

main.py ticket system
read_tickets.py headless browser simulating an admin reading tickets
want to log in as admin, but password cannot be recovered
read_tickets.py admin gets session cookie, goal is to steal session cookie

# XSS vulnerability

main.py get_ticket_by_id returns raw ticket
if ticket rendered by browser, could result in JS code execution
read_tickets.py ticket is rendered by browser

# XSS payload

maybe a ticket with <script> payload?
/tickets endpoint has a simple XSS blacklist
how to bypass? one solution: iframe (https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#iframe)
requestcatcher.com

# Logging in as admin

# Conclusion


