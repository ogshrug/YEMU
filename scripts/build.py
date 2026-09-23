"""
Build YEMU release artifacts into dist/:

  yemu-<ver>-py3-none-any.whl, yemu-<ver>.tar.gz     Python packages
  YEMU-<ver>-windows-x64.zip | YEMU-<ver>-linux-x86_64.tar.gz   PyInstaller bundle
  YEMU-<ver>-windows-x64-setup.exe                   Windows installer (needs Inno Setup, --installer)

Everything is built from a fresh virtualenv (.build-venv) so unrelated packages from
the developer's machine never end up in the bundle. The frozen executables are
smoke-tested before anything is archived.

  python scripts/build.py [--installer] [--skip-bundle] [--keep-venv]
"""
import argparse
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import venv
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"
VENV = ROOT / ".build-venv"
IS_WIN = sys.platform == "win32"


def run(*cmd, env=None, cwd=ROOT):
    print("+", " ".join(str(c) for c in cmd), flush=True)
    subprocess.run([str(c) for c in cmd], check=True, cwd=cwd, env=env)


def version():
    ns = {}
    exec((ROOT / "yemu" / "__init__.py").read_text(encoding="utf-8"), ns)
    return ns["__version__"]


def venv_python():
    if not VENV.exists():
        print(f"Creating {VENV}")
        venv.create(VENV, with_pip=True)
    py = VENV / ("Scripts/python.exe" if IS_WIN else "bin/python")
    run(py, "-m", "pip", "install", "--quiet", "--upgrade", "pip")
    run(py, "-m", "pip", "install", "--quiet", "-e", ".[gui]", "pyinstaller>=6.6", "build")
    return py


def build_python_packages(py):
    run(py, "-m", "build", "--outdir", DIST)


def build_bundle(py, ver):
    shutil.rmtree(ROOT / "build", ignore_errors=True)
    shutil.rmtree(DIST / "YEMU", ignore_errors=True)
    run(py, "-m", "PyInstaller", "packaging/yemu.spec", "--noconfirm", "--log-level", "WARN",
        "--distpath", DIST, "--workpath", ROOT / "build")
    bundle = DIST / "YEMU"
    exe = ".exe" if IS_WIN else ""

    # smoke tests against a throwaway data folder
    env = {**os.environ, "YEMU_HOME": str(ROOT / "build" / "smoke-home"), "QT_QPA_PLATFORM": "offscreen",
           "YEMU_SMOKE_TEST": "1"}
    run(bundle / f"yemu{exe}", "--version", env=env)
    run(bundle / f"yemu{exe}", "doctor", env=env)
    sample = ROOT / "build" / "smoke-sample.sh"
    sample.write_text("encrypt decrypt .locked\ncurl http://example.invalid\n", encoding="utf-8")
    run(bundle / f"yemu{exe}", "analyze", sample, "--backend", "mock", "--pcap", env=env)
    run(bundle / f"yemu-gui{exe}", env=env)

    arch = "x64" if platform.machine().lower() in ("amd64", "x86_64") else platform.machine().lower()
    if IS_WIN:
        out = DIST / f"YEMU-{ver}-windows-{arch}.zip"
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
            for f in bundle.rglob("*"):
                z.write(f, Path("YEMU") / f.relative_to(bundle))
    else:
        out = DIST / f"YEMU-{ver}-linux-{'x86_64' if arch == 'x64' else arch}.tar.gz"
        with tarfile.open(out, "w:gz") as t:
            t.add(bundle, arcname="YEMU")
            for extra in ("install.sh", "io.github.ogshrug.YEMU.desktop"):
                t.add(ROOT / "packaging" / "linux" / extra, arcname=extra)
    print(f"Bundle: {out}")
    return bundle


def find_iscc():
    candidates = [shutil.which("iscc"), shutil.which("ISCC")]
    for base in (os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles"),
                 os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs")):
        if base:
            candidates.append(os.path.join(base, "Inno Setup 6", "ISCC.exe"))
    return next((c for c in candidates if c and os.path.isfile(c)), None)


def build_installer(ver):
    iscc = find_iscc()
    if not iscc:
        sys.exit("Inno Setup (ISCC.exe) not found. Install it (winget install JRSoftware.InnoSetup) or drop --installer.")
    run(iscc, f"/DAppVersion={ver}", f"/DSourceDir={DIST / 'YEMU'}", f"/DOutputDir={DIST}",
        ROOT / "packaging" / "windows" / "yemu.iss")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--installer", action="store_true", help="also build the Windows installer (Inno Setup)")
    parser.add_argument("--skip-bundle", action="store_true", help="only build the wheel and sdist")
    parser.add_argument("--keep-venv", action="store_true", help="reuse .build-venv instead of recreating it")
    args = parser.parse_args()

    if not args.keep_venv:
        shutil.rmtree(VENV, ignore_errors=True)
    DIST.mkdir(exist_ok=True)
    ver = version()
    py = venv_python()
    build_python_packages(py)
    if not args.skip_bundle:
        build_bundle(py, ver)
        if args.installer:
            if not IS_WIN:
                sys.exit("--installer is only supported on Windows")
            build_installer(ver)
    print("\nArtifacts:")
    for f in sorted(DIST.iterdir()):
        if f.is_file():
            print(f"  {f.name}  ({f.stat().st_size / 1048576:.1f} MB)")


if __name__ == "__main__":
    main()
