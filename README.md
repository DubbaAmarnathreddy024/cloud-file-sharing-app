# Cloud File-Sharing App

A Flask-based cloud-style file-sharing web application for a Computer
Networks / cloud deployment project. It supports user accounts,
encrypted file storage, file sharing, and deployment on an Ubuntu
virtual machine so it can be accessed from another computer on an
authorized network.

> **Project scope:** "Cloud" means the application is hosted on a VM
> with persistent storage. Files are stored on that VM's disk and
> encrypted at rest. This project does not integrate with AWS S3, Azure
> Blob Storage, or Google Cloud Storage.

## Features

-   User registration, login, and logout.
-   Password hashing and session-based access control.
-   Private file upload, download, and deletion.
-   File encryption at rest using Fernet.
-   SHA-256 integrity verification.
-   Sharing files with another registered user, with the ability to
    revoke access.
-   Seven-day share links that can be revoked.
-   Random storage names; original filenames are metadata rather than
    storage paths.
-   Upload-size limits and secure filename handling.
-   CSRF protection on POST forms.
-   Parameterized SQL queries and user-specific authorization checks.
-   SQLite database and local encrypted-file storage.
-   `/health` endpoint for basic deployment checks.

## Technology Stack

-   **Backend:** Python, Flask
-   **Database:** SQLite
-   **Encryption:** Fernet (`cryptography`)
-   **Integrity checks:** SHA-256
-   **Web server:** Flask development server for local testing; Gunicorn
    for VM deployment
-   **Deployment target:** Ubuntu VM in Oracle VirtualBox or another
    authorized VM environment

## Project Structure

``` text
Cloud-File-Sharing-App/
├── app.py
├── requirements.txt
├── Procfile
├── .env.example
├── README.md
├── .gitignore
├── tests/
├── templates/
├── static/
│   └── style.css
├── instance/          # generated database and encryption key; keep private
└── storage/           # encrypted file blobs; persistent disk required
```

The exact contents may vary slightly depending on your current project
version. The `instance/` and `storage/` directories may be generated at
runtime.

## Requirements

-   Python 3.10 or newer recommended
-   pip and Python virtual-environment support
-   Windows, Linux, or Ubuntu
-   For VM deployment: an Ubuntu VM and network access from the client
    computer

## Run Locally

### Windows PowerShell

Open PowerShell in the project directory:

``` powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
$env:FLASK_SECRET_KEY = (python -c "import secrets; print(secrets.token_hex(32))")
python app.py
```

Open <http://127.0.0.1:5000> in your browser.

### Linux / Ubuntu

Open a terminal in the project directory:

``` bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
export FLASK_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
python app.py
```

Open <http://127.0.0.1:5000> in a browser on the same machine.

The development server is intended for local testing only. Do not use
Flask's development server as the public production server.

## Deploy on an Ubuntu VM

Use only a VM and network that you own or are authorized to administer.

### 1. Install system packages

``` bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
```

### 2. Place the application on the VM

Copy or clone the project into a suitable application directory. The
example below assumes `/opt/cloudshare/app` contains the source code and
that persistent data will live outside the source tree.

``` bash
sudo useradd --system --create-home --home-dir /opt/cloudshare --shell /usr/sbin/nologin cloudshare
sudo mkdir -p /opt/cloudshare/app /opt/cloudshare/data/instance /opt/cloudshare/data/storage
sudo chown -R cloudshare:cloudshare /opt/cloudshare
```

Copy the project files into `/opt/cloudshare/app` using your preferred
method, then set ownership:

``` bash
sudo chown -R cloudshare:cloudshare /opt/cloudshare/app
```

Create a virtual environment and install dependencies:

``` bash
sudo -u cloudshare python3 -m venv /opt/cloudshare/app/.venv
sudo -u cloudshare /opt/cloudshare/app/.venv/bin/pip install --upgrade pip
sudo -u cloudshare /opt/cloudshare/app/.venv/bin/pip install -r /opt/cloudshare/app/requirements.txt
```

Ensure `gunicorn` is listed in `requirements.txt` if you use the service
configuration below.

### 3. Configure secrets and persistent storage

Create a root-readable environment file:

``` bash
sudo install -m 600 /dev/null /etc/cloudshare.env
sudo nano /etc/cloudshare.env
```

Add these lines, replacing the placeholder with a newly generated
secret:

``` dotenv
FLASK_SECRET_KEY=REPLACE_WITH_A_LONG_RANDOM_SECRET
CLOUDSHARE_INSTANCE_DIR=/opt/cloudshare/data/instance
CLOUDSHARE_STORAGE_DIR=/opt/cloudshare/data/storage
COOKIE_SECURE=0
```

Generate a random Flask secret on the VM:

``` bash
python3 -c 'import secrets; print(secrets.token_hex(32))'
```

Copy the output into `FLASK_SECRET_KEY`. Keep `/etc/cloudshare.env`
private and never commit it to Git.

**Important:** Check that the application code actually reads
`CLOUDSHARE_INSTANCE_DIR`, `CLOUDSHARE_STORAGE_DIR`, and
`COOKIE_SECURE`. Environment-variable names in documentation do not
configure the application unless the code supports them.

The app may generate `instance/fernet.key` and a Flask secret key on
first start if no override is supplied. Back up the Fernet key securely.
Files encrypted with a key cannot be recovered if that key is lost. Keep
the database, matching encryption key, and encrypted file blobs backed
up together.

If you use a `FERNET_KEY` environment override, generate it using the
`cryptography` package:

``` bash
/opt/cloudshare/app/.venv/bin/python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

Only configure this variable if the application supports it.

### 4. Create a systemd service

Create the service file:

``` bash
sudo nano /etc/systemd/system/cloudshare.service
```

Example configuration:

``` ini
[Unit]
Description=Cloud File-Sharing App
After=network.target

[Service]
User=cloudshare
Group=cloudshare
WorkingDirectory=/opt/cloudshare/app
EnvironmentFile=/etc/cloudshare.env
Environment=PYTHONUNBUFFERED=1
ExecStart=/opt/cloudshare/app/.venv/bin/gunicorn --workers 2 --bind 0.0.0.0:5000 --access-logfile - --error-logfile - app:app
Restart=on-failure
RestartSec=3
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

This example assumes the Flask application object is named `app` in
`app.py`. Confirm this in your code before using the service.

Start the service:

``` bash
sudo systemctl daemon-reload
sudo systemctl enable --now cloudshare
sudo systemctl status cloudshare --no-pager
```

Check the health endpoint locally:

``` bash
curl http://127.0.0.1:5000/health
```

If the service fails, inspect its logs:

``` bash
sudo journalctl -u cloudshare -n 100 --no-pager
```

### 5. Access the VM from another computer

Find the VM's IP address:

``` bash
hostname -I
```

From another computer on the same trusted network, open:

``` text
http://VM_IP_ADDRESS:5000
```

Replace `VM_IP_ADDRESS` with the reachable address of your VM.

-   For a VirtualBox VM, bridged networking is often convenient when the
    client is on the same LAN.
-   With NAT networking, configure appropriate port forwarding if
    required.
-   Allow TCP port 5000 only on the trusted network or VM
    firewall/security rules.
-   Do not expose this plain HTTP service directly to the public
    internet.

For public or untrusted networks, use a reverse proxy such as Nginx with
HTTPS, set secure cookies (`COOKIE_SECURE=1` if supported), configure
proxy headers carefully, and expose HTTPS rather than the bare
Flask/Gunicorn port.

## Configuration Reference

The following variables are documented for deployments that support
them. Verify names and behavior against the current `app.py` before
relying on them.

  -----------------------------------------------------------------------------------------
  Variable                    Purpose                 Example / default
  --------------------------- ----------------------- -------------------------------------
  `FLASK_SECRET_KEY`          Signs Flask sessions    Set a long random value

  `FERNET_KEY`                Optional encryption-key Only if supported by the application
                              override                

  `CLOUDSHARE_INSTANCE_DIR`   Database and key        `./instance`
                              directory               

  `CLOUDSHARE_STORAGE_DIR`    Encrypted file          `./storage`
                              directory               

  `CLOUDSHARE_DB_PATH`        Optional explicit       `<instance-dir>/cloudshare.sqlite3`
                              SQLite path             

  `MAX_UPLOAD_MB`             Maximum upload size     `25`

  `COOKIE_SECURE`             Secure cookie flag for  `0` locally; `1` behind HTTPS
                              HTTPS                   

  `ALLOWED_EXTENSIONS`        Optional extension      Unrestricted if not configured
                              allowlist               
  -----------------------------------------------------------------------------------------

## Demo Checklist

1.  Register User A and User B in separate browser sessions.
2.  Log in as User A and upload a test document.
3.  Download the file and verify its contents or integrity status.
4.  Share the file with User B by username.
5.  Log in as User B and download it from **Shared with me**.
6.  Revoke User B's access and confirm that the user can no longer
    access the shared file.
7.  Create a seven-day share link and open it in a private browser
    window.
8.  Download the shared file through the link, revoke the link, and
    confirm it no longer works.
9.  Access the VM's IP address from a second computer on the authorized
    network.
10. Restart the service and verify that the database, keys, accounts,
    and uploaded files persist.

## Automated Tests

After installing dependencies, run:

``` bash
python -m unittest discover -s tests -v
```

Confirm the tests exist and pass in your current checkout. Tests should
use temporary directories and a disposable database so they do not alter
real user files.

## Security Scope and Limitations

-   Share links are bearer links: anyone who obtains an active link may
    be able to download the associated file. Treat links like secrets
    and revoke them when no longer needed.
-   Encryption at rest protects stored file contents, but the server
    holds or can access the encryption key to decrypt files for
    authorized downloads. This is not zero-knowledge or end-to-end
    encryption.
-   Use HTTPS on untrusted networks. Do not enable Flask debug mode in
    production.
-   Add rate limiting, monitoring, tested backups, malware scanning, and
    an external object-storage backend before considering use with
    sensitive production data.
-   SQLite and a single VM are suitable for a student project/demo, not
    a high-availability production service.
-   Back up the SQLite database, matching Fernet key, and encrypted file
    blobs together. Keep backups private.
-   Never commit `.env` files, generated keys, the `instance/`
    directory, private databases, uploaded documents, or the `storage/`
    directory to Git.

## License

Add a license file if you intend to publish this project for reuse. Do
not claim a license until you have chosen one.
