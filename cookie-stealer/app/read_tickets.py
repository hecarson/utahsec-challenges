import os
import time
from datetime import datetime
from selenium import webdriver
import requests

BASE_URL = "http://localhost:10000"

def log(m):
    print(f"[read_tickets] [{datetime.now().isoformat()}] {m}")

def read_tickets():
    # Log in as admin
    credentials = {
        "username": "admin",
        "password": os.environ["ADMIN_PW"]
    }
    res = requests.post(BASE_URL + "/login", data=credentials, allow_redirects=False)
    if not res.ok:
        log(f"Admin login failed, status code {res.status_code}")
        return
    if "session" not in res.cookies:
        log(f"Admin login failed, no session cookie")
        return
    session_cookie = res.cookies["session"]

    # Get ticket ids
    res = requests.get(BASE_URL + "/admin/tickets/", cookies={"session": session_cookie})
    if not res.ok:
        log(f"Failed to fetch ticket ids, status code {res.status_code}")
        return
    ticket_ids = res.json()

    options = webdriver.ChromeOptions()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    driver = webdriver.Chrome(options=options)
    driver.get(BASE_URL + "/")
    driver.add_cookie({"name": "session", "value": session_cookie})

    for ticket_id in ticket_ids:
        try:
            driver.get(BASE_URL + f"/admin/tickets/{ticket_id}")
            # Wait for page to load
            time.sleep(0.5)
            # Save ticket screenshot
            driver.save_screenshot(f"tickets/{ticket_id}.png")
        except Exception as e:
            log(e)

        # Delete ticket
        res = requests.delete(BASE_URL + f"/admin/tickets/{ticket_id}", cookies={"session": session_cookie})
        if not res.ok:
            log(f"Delete failed, ticket id {ticket_id}")

    driver.quit()



if __name__ == "__main__":
    while True:
        time.sleep(5)
        try:
            read_tickets()
        except Exception as e:
            log(e)
