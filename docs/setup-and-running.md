# Setup and Running Guide

## 1. Requirements

Install the following software before running the project:

- Python 3.11 or a compatible Python version.
- Git, if cloning the repository.
- Streamlit and the Python dependencies listed in `requirements.txt`.
- An Ubuntu virtual machine running Cowrie, if collecting live honeypot events.

## 3. Get the Project Ready

Open PowerShell and navigate to the project directory:

```powershell
cd "D:\Documents\GitHub\honeypot-cyberattack-intelligence"
```

Create and activate a virtual environment if you do not already have one:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install the project dependencies:

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell prevents virtual-environment activation, you can run the Python commands using `.venv\Scripts\python.exe` directly instead.

## 4. Configure Cowrie Log Access

Cowrie commonly stores its JSON event log on the Ubuntu VM at:

```text
/home/cowrie/cowrie/var/log/cowrie/cowrie.json
```

Verify that the file exists on the Ubuntu VM:

```bash
ls -lh /home/cowrie/cowrie/var/log/cowrie/cowrie.json
```

If the project uses a VirtualBox shared folder named `cowrie-share`, the folder may be mounted in Ubuntu at:

```text
/media/sf_cowrie-share
```

Copy the log into the shared folder:

```bash
sudo cp /home/cowrie/cowrie/var/log/cowrie/cowrie.json /media/sf_cowrie-share/cowrie.json
```

On the Windows host, the corresponding shared folder in this setup is:

```text
D:\cowrie-share
```

Confirm that `cowrie.json` is present there before running the pipeline. Actual paths can differ depending on your VM and VirtualBox configuration.

## 5. Run the Data Pipeline

From the project root in PowerShell, run:

```powershell
python -c "from src.pipeline import run_pipeline; print(run_pipeline(r'D:\cowrie-share\cowrie.json'))"
```

The pipeline reads the Cowrie JSON log, normalizes valid events, stores them in SQLite, and produces a summary and alerts.

The output includes summary information such as:

- Total events
- Unique source IP addresses
- Successful logins
- Failed logins
- Command events
- Unique sessions

It can also report alerts for detected activity.

**Note:** This command processes the log when it is run. It does not continuously monitor the log in real time.

## 6. Launch the Dashboard

Run the dashboard from the **project root**, not from inside the `dashboard` directory:

```powershell
python -m streamlit run dashboard/dashboard_streamlit.py
```

Streamlit will display a local URL in the terminal.
## 7. Database

The default SQLite database path is:

```text
data/honeypot.db
```

The database stores normalized events in the `events` table.

The storage module provides functions to initialize the database, insert events, and retrieve stored events. Duplicate prevention is implemented by the storage layer.

If you use a different database path, make sure the pipeline and dashboard are configured to use the intended database.

## 8. Run the Tests

From the project root, execute:

```powershell
python -m pytest -v
```

Review the test results and resolve any failures before considering a change complete.

## 9. Troubleshooting

### Python cannot find `src`

If you see:

```text
ModuleNotFoundError: No module named 'src'
```

First navigate to the project root:

```powershell
cd "D:\Documents\GitHub\honeypot-cyberattack-intelligence"
```

Test the import:

```powershell
python -c "from src.storage import DEFAULT_DB_PATH, get_events, init_db; print('Import successful')"
```

Then launch Streamlit from the same project root:

```powershell
python -m streamlit run dashboard/dashboard_streamlit.py
```

If the import still fails, check that the `src` directory exists and contains the expected project modules.

### Cowrie log file cannot be found

On Windows, check the shared folder:

```powershell
Get-ChildItem "D:\cowrie-share"
```

On Ubuntu, check the Cowrie log path using the `ls -lh` command in Section 4.

### Streamlit cannot find the dashboard file

Check the dashboard directory:

```powershell
Get-ChildItem dashboard
```

Confirm that `dashboard_streamlit.py` exists before launching it.

### Dashboard shows no events

Confirm that:
1. The pipeline completed without an error.
2. The input log contains valid Cowrie JSON events.
3. The pipeline and dashboard use the same SQLite database.
4. The events meet the collector's validation requirements.

## 10. Typical Workflow

1. Start the Ubuntu VM and ensure Cowrie is running.
2. Copy the Cowrie JSON log into the shared folder.
3. Open PowerShell in the project root.
4. Activate the virtual environment, if applicable.
5. Run the pipeline.
6. Launch the Streamlit dashboard.
7. Review event summaries and alerts.
8. Run the test suite after making code changes.
