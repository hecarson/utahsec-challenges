# cookie-stealer | Web Exploitation | UtahSec 2025-MM-DD

Author: Carson He (zakstamaj)

CTF technical skills workshop on XSS to steal a cookie.

Challenge website: 

## Initial analysis

main.py flag in admin panel
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


