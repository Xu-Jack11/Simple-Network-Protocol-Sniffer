# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

# Ensure the ui directory and its contents are correctly bundled.
# Also include config.py and utils.py at the root level.
datas = [
    ('ui', 'ui'), 
    ('config.py', '.'), 
    ('utils.py', '.'),
    ('README.md', '.') # Optional: include README in the bundle
]

# Add an icon if you have one, e.g., icon.ico in the root directory
app_icon = 'icon.ico' if os.path.exists('icon.ico') else None

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=[
        'PyQt5.sip',
        'PyQt5.QtCore',
        'PyQt5.QtGui',
        'PyQt5.QtWidgets',
        'scapy.all', # Or be more specific if you know exactly which submodules
        'matplotlib.pyplot',
        'matplotlib.backends.backend_qt5agg',
        'psutil'
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='NetworkProtocolSniffer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False, # Set to False for a GUI application, True for a console application
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=app_icon,
    # Remove version file reference to avoid parse errors
    # version=None
)
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='NetworkProtocolSniffer'
)