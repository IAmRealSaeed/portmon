# Builds dist/install_portmon.sh: install.sh with the app and fonts embedded, for servers that cannot reach GitHub.
# Copy it to the server and run:  sudo bash install_portmon.sh
import base64, os
HERE = os.path.dirname(os.path.abspath(__file__))
FILES = ["portmon.py", "fonts/Vazirmatn-Regular.woff2", "fonts/Vazirmatn-Bold.woff2"]

body = open(os.path.join(HERE, "install.sh"), encoding="utf-8").read()
shebang, rest = body.split("\n", 1)
head = [shebang, "# Offline build of install.sh (app + fonts embedded); made by make_installer.py.",
        'PM_SRC=$(mktemp -d); trap \'rm -rf "$PM_SRC"\' EXIT; export PM_SRC; mkdir -p "$PM_SRC/fonts"']
for f in FILES:
    data = base64.encodebytes(open(os.path.join(HERE, f), "rb").read()).decode()
    head.append(f"base64 -d > \"$PM_SRC/{f}\" <<'B64'\n{data}B64")
os.makedirs(os.path.join(HERE, "dist"), exist_ok=True)
out = os.path.join(HERE, "dist", "install_portmon.sh")
with open(out, "w", newline="\n", encoding="utf-8") as fh:
    fh.write("\n".join(head) + "\n" + rest)
print(f"{out}: {os.path.getsize(out)} bytes")
