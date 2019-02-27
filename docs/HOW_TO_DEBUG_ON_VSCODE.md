How to debug on Visual Studio Code
==============================================

This manual provedes a step-by-step guide on how to debug on Visual Studio Code.

## Debug a pyocd</span>.py

1. Get [ptvsd](https://pypi.org/project/ptvsd/).
```
pip install ptvsd
```
2. Modify a pyocd</span>.py like this.
```diff
--- a/pyocd/tools/pyocd.py
+++ b/pyocd/tools/pyocd.py
@@ -25,6 +25,7 @@ import optparse
from optparse import make_option
import traceback
import six
+import ptvsd

# Attempt to import readline.
try:
@@ -1545,6 +1546,11 @@ class PyOCDTool(object):


def main():
+    # Allow other computers to attach to ptvsd at this IP address and port.
+    ptvsd.enable_attach(address=('123.123.123.123', 3000), redirect_output=True)
+
+    # Pause the program until a remote debugger is attached
+    ptvsd.wait_for_attach()
    sys.exit(PyOCDTool().run())
```
3. Create launch.json on pyOCD directry.
```json
// PATH_TO_PYOCD\launch.json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Python: pyocd",
            "type": "python",
            "request": "attach",
            "port": 3000, // Set to the remote port.
            "host": "123.123.123.123" // Set to your remote host's public IP address.
            },
    ]
}
```
4. Connect target board to PC.
5. Run pyocd</span>.py
```
PS C:\Users\User\Documents\GitHub\pyOCD>python.exe -m pyocd.tools.pyocd
```
6. Start Debugging

Select Debug -> Start Debigging on Visual Studio Code.


## Reference

[Python debug configurations in Visual Studio Code](https://code.visualstudio.com/docs/python/debugging/)

[Attach to a local script](https://code.visualstudio.com/docs/python/debugging#_attach-to-a-local-script)


