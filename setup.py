#!/usr/bin/env python3
"""
php2shell-scanner one-click setup.

    python3 setup.py

What it does:
  1. Finds a Python interpreter that is 3.8 or newer (the scanner's minimum).
     - If the interpreter currently running this script already qualifies, it's used directly.
     - If not (e.g. a very old system "python3"), it looks for a newer one already on PATH
       (python3.8 .. python3.14), and failing that, offers to install one with pyenv
       (installing pyenv itself first if needed) and uses that.
  2. Creates an isolated virtual environment in .venv/ with that interpreter, so this never
     touches your system or Homebrew/apt Python (relevant on newer distros and macOS, which
     mark the system Python "externally managed" and refuse bare `pip install`).
  3. The scanner itself has zero third-party dependencies (standard library only), so there is
     nothing to download for it; this step only makes sure pip/venv exist and installs anything
     listed in requirements.txt (currently none) for future-proofing.
  4. Prints the exact commands to run the scanner, and offers to launch the GUI immediately.

Safe to re-run; it reuses the existing .venv/ if one is already set up correctly.
Only installs software (pyenv, a Python version) with your explicit "y" at a prompt;
pass --yes / --non-interactive to skip prompts (CI use), or --no-pyenv to never touch pyenv.
"""
import argparse
import os
import platform
import shutil
import subprocess
import sys
import venv

MIN_VERSION = (3, 8)
PREFERRED_VERSION = "3.12.9"  # used only if we have to install a fresh interpreter via pyenv
HERE = os.path.dirname(os.path.abspath(__file__))
VENV_DIR = os.path.join(HERE, ".venv")
IS_WINDOWS = platform.system() == "Windows"


def say(msg):
    print(f"[setup] {msg}", flush=True)


def run(cmd, **kw):
    say("$ " + " ".join(cmd))
    return subprocess.run(cmd, check=True, **kw)


def ask(prompt, default_yes, args):
    if args.yes:
        return True
    if args.non_interactive:
        return False
    hint = "Y/n" if default_yes else "y/N"
    try:
        ans = input(f"{prompt} [{hint}] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return default_yes
    if not ans:
        return default_yes
    return ans in ("y", "yes")


def version_of(python_exe):
    """(major, minor) of a python executable, or None if it can't be run."""
    try:
        out = subprocess.run([python_exe, "-c", "import sys; print(sys.version_info[0], sys.version_info[1])"],
                             capture_output=True, text=True, timeout=10)
        if out.returncode != 0:
            return None
        major, minor = out.stdout.split()
        return (int(major), int(minor))
    except Exception:
        return None


def find_suitable_python():
    """Return a path to a Python >= MIN_VERSION, searching PATH if the current interpreter is too old."""
    if sys.version_info[:2] >= MIN_VERSION:
        return sys.executable, sys.version_info[:2]

    say(f"Running under Python {sys.version_info.major}.{sys.version_info.minor}, "
        f"but php2shell-scanner needs {MIN_VERSION[0]}.{MIN_VERSION[1]}+. Looking for a newer interpreter on PATH...")
    candidates = [f"python3.{m}" for m in range(14, 7, -1)] + ["python3"]
    for name in candidates:
        exe = shutil.which(name)
        if not exe:
            continue
        v = version_of(exe)
        if v and v >= MIN_VERSION:
            say(f"Found {name} -> {exe} (Python {v[0]}.{v[1]})")
            return exe, v
    return None, None


def pyenv_root():
    exe = shutil.which("pyenv")
    if exe:
        return exe
    guess = os.path.join(os.path.expanduser("~"), ".pyenv", "bin", "pyenv")
    return guess if os.path.exists(guess) else None


def install_pyenv_if_needed(args):
    exe = pyenv_root()
    if exe:
        return exe
    if IS_WINDOWS:
        say("pyenv is not available on native Windows. Install Python 3.8+ manually from "
            "https://www.python.org/downloads/windows/ and re-run this script, or use WSL.")
        return None
    if not ask("pyenv (a Python version manager) was not found. Install it now?", True, args):
        return None
    say("Installing pyenv...")
    try:
        if shutil.which("brew") and platform.system() == "Darwin":
            run(["brew", "install", "pyenv"])
        else:
            # Official installer: https://github.com/pyenv/pyenv-installer
            script = subprocess.run(["curl", "-fsSL", "https://pyenv.run"], capture_output=True, text=True,
                                    check=True, timeout=30).stdout
            subprocess.run(["bash"], input=script, text=True, check=True)
    except Exception as e:
        say(f"Automatic pyenv install failed ({e}). Install it yourself: https://github.com/pyenv/pyenv#installation")
        return None
    exe = pyenv_root()
    if not exe:
        say("pyenv installed but not found on PATH in this shell. Open a new terminal (so your "
            "shell profile picks up pyenv) and re-run: python3 setup.py")
        return None
    return exe


def python_via_pyenv(args):
    pyenv_exe = install_pyenv_if_needed(args)
    if not pyenv_exe:
        return None
    say(f"Installing Python {PREFERRED_VERSION} via pyenv (only if not already installed)...")
    try:
        run([pyenv_exe, "install", "--skip-existing", PREFERRED_VERSION])
    except subprocess.CalledProcessError as e:
        say(f"pyenv install failed: {e}")
        return None
    root = subprocess.run([pyenv_exe, "root"], capture_output=True, text=True, check=True).stdout.strip()
    exe = os.path.join(root, "versions", PREFERRED_VERSION, "bin", "python3")
    return exe if os.path.exists(exe) else None


def venv_python(venv_dir):
    return os.path.join(venv_dir, "Scripts", "python.exe") if IS_WINDOWS else os.path.join(venv_dir, "bin", "python3")


def existing_venv_is_usable(venv_dir):
    exe = venv_python(venv_dir)
    return os.path.exists(exe) and version_of(exe) is not None and version_of(exe) >= MIN_VERSION


def create_venv(base_python, venv_dir):
    say(f"Creating virtual environment at {os.path.relpath(venv_dir, HERE)} with {base_python} ...")
    if base_python == sys.executable:
        venv.EnvBuilder(with_pip=True, clear=True).create(venv_dir)
    else:
        # A different interpreter (e.g. one just installed via pyenv): let IT build its own venv,
        # since the running interpreter's venv module can only clone itself reliably.
        run([base_python, "-m", "venv", "--clear", venv_dir])


def pip_install_requirements(py_exe):
    req = os.path.join(HERE, "requirements.txt")
    run([py_exe, "-m", "pip", "install", "--upgrade", "pip"], stdout=subprocess.DEVNULL)
    if os.path.exists(req) and open(req, encoding="utf-8").read().strip():
        run([py_exe, "-m", "pip", "install", "-r", req])
    else:
        say("No third-party dependencies to install (scanner.py uses only the standard library).")


def externally_managed(py_exe):
    try:
        out = subprocess.run([py_exe, "-c",
                              "import sysconfig, os; print(os.path.exists(os.path.join("
                              "sysconfig.get_path('stdlib'), 'EXTERNALLY-MANAGED')))"],
                             capture_output=True, text=True, timeout=10)
        return out.stdout.strip() == "True"
    except Exception:
        return False


def print_next_steps(py_exe):
    rel_py = os.path.relpath(py_exe, HERE)
    activate = (r".venv\Scripts\activate" if IS_WINDOWS else "source .venv/bin/activate")
    print()
    print("=" * 70)
    print(" Setup complete.")
    print("=" * 70)
    print(f"\n Run the GUI:\n     {rel_py} scanner.py\n")
    print(f" Or from the command line:\n     {rel_py} scanner.py --cli --authorized -t example.com\n")
    print(f" To use the venv directly in this shell:\n     {activate}\n     python3 scanner.py\n")
    print(" Remember: only scan hosts you are authorized to test.")
    print("=" * 70)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--yes", action="store_true", help="assume yes to every prompt (installs pyenv/Python if needed)")
    ap.add_argument("--non-interactive", action="store_true", help="never prompt; fail instead of installing things")
    ap.add_argument("--no-pyenv", action="store_true", help="never try to install or use pyenv")
    ap.add_argument("--launch", action="store_true", help="after setup, immediately start the GUI")
    args = ap.parse_args()

    say(f"Detected OS: {platform.system()} {platform.release()} | this interpreter: Python "
        f"{sys.version.split()[0]} at {sys.executable}")

    if existing_venv_is_usable(VENV_DIR):
        say(f"Reusing existing virtual environment at {os.path.relpath(VENV_DIR, HERE)}")
        py_exe = venv_python(VENV_DIR)
    else:
        base_python, ver = find_suitable_python()
        via_pyenv = False
        if not base_python and not args.no_pyenv:
            base_python = python_via_pyenv(args)
            ver = version_of(base_python) if base_python else None
            via_pyenv = base_python is not None
        if not base_python:
            sys.exit(f"error: could not find or install a Python {MIN_VERSION[0]}.{MIN_VERSION[1]}+ interpreter. "
                     "Install one from https://www.python.org/downloads/ and re-run this script.")
        say(f"Using Python {ver[0]}.{ver[1]} at {base_python}" + (" (newly installed via pyenv)" if via_pyenv else ""))
        if externally_managed(base_python):
            say("This system Python is 'externally managed' (PEP 668) - using a venv avoids the "
                "'externally-managed-environment' pip error, which is exactly what we're doing next.")
        create_venv(base_python, VENV_DIR)
        py_exe = venv_python(VENV_DIR)

    pip_install_requirements(py_exe)
    print_next_steps(py_exe)

    # Deliberately NOT gated by --yes: that flag means "yes to installing things", not "yes to
    # starting a server and blocking this terminal". Launching needs --launch, or an interactive y.
    want_launch = args.launch
    if not want_launch and not args.yes and not args.non_interactive:
        want_launch = ask("Launch the scanner GUI now?", False, args)
    if want_launch:
        os.execv(py_exe, [py_exe, os.path.join(HERE, "scanner.py")])


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as e:
        sys.exit(f"error: command failed ({e})")
    except KeyboardInterrupt:
        sys.exit("\nAborted.")
