# Sent Eye Dev Container

This file pins the environment so GitHub Codespaces rebuilds cleanly:

- Installs **ExifTool** (`libimage-exiftool-perl`) on container creation
- Installs Python dependencies from `requirements.txt`
- Enables the Python + Pylance VS Code extensions

**Not included** (to keep rebuilds fast): `dlib` + `face_recognition`.
Face analysis requires a 5–10 minute source build, so it's opt-in:

    pip install -r requirements-faces.txt

The `pkg_resources` shim in `backend/compat.py` means you do **not** need to
pin `setuptools<82`.

## When does this run?

`postCreateCommand` runs once per container creation — i.e., when the
Codespace is first created or rebuilt. It does **not** re-run on every
open. If you change `requirements.txt` and want the change applied,
either rebuild the container or run `pip install -r requirements.txt`
manually.
