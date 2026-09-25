# PyInstaller spec for "Protocol Toolkit.app". Build with packaging/macos/build_app.sh
import os
import sys

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ROOT = os.path.abspath(os.path.join(SPECPATH, "..", ".."))  # noqa: F821 (SPECPATH is set by PyInstaller)
sys.path.insert(0, ROOT)
from protocol_toolkit import __version__  # noqa: E402

hidden = (collect_submodules("uvicorn") + collect_submodules("websockets")
          + collect_submodules("aioquic") + ["pylsqpack", "hpack", "brotli", "certifi"])
datas = collect_data_files("certifi") + [(os.path.join(ROOT, "protocol_toolkit", "webapp", "static"),
                                          "protocol_toolkit/webapp/static")]

a = Analysis([os.path.join(SPECPATH, "launcher.py")],  # noqa: F821
             pathex=[ROOT], datas=datas, hiddenimports=hidden,
             excludes=["tkinter", "matplotlib", "numpy", "pandas", "scipy", "pygame", "IPython", "jupyter", "notebook", "pytest", "setuptools", "pkg_resources"], noarchive=False)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="Protocol Toolkit", console=False,
          argv_emulation=False, target_arch=None)
coll = COLLECT(exe, a.binaries, a.datas, name="Protocol Toolkit")
app = BUNDLE(
    coll,
    name="Protocol Toolkit.app",
    icon=os.path.join(SPECPATH, "AppIcon.icns"),  # noqa: F821
    bundle_identifier="io.github.vaibhav375.protocoltoolkit",
    version=__version__,
    info_plist={
        "CFBundleName": "Protocol Toolkit",
        "CFBundleDisplayName": "Protocol Toolkit",
        "CFBundleShortVersionString": __version__,
        "NSHighResolutionCapable": True,
        "LSMinimumSystemVersion": "12.0",
        "NSHumanReadableCopyright": "Vaibhav Handoo",
    },
)
