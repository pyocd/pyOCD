---
title: Environment variables
---

<table>

<tr><th>Variable</th><th>Description</th></tr>

<tr><td>
<a if="pyocd_project_dir"><p><code>PYOCD_COLOR</code></p></a>
</td><td>
<p>Changes the default color output setting. Must be one of <code>auto</code>, <code>always</code>, or
<code>never</code>. If not defined, the default is <code>auto</code>, which will enable color only when
outputting to a tty. Overridden by <code>--color</code> on the command line.</p>
</td></tr>

<tr><td>
<a if="pyocd_history"><p><code>PYOCD_HISTORY</code></p></a>
</td><td>
<p>Path to the <code>pyocd commander</code> command history file. The default is <code>~/.pyocd_history</code>.</p>
</td></tr>

<tr><td>
<a if="pyocd_history_length"><p><code>PYOCD_HISTORY_LENGTH</code></p></a>
</td><td>
<p>Maximum number of entries in the command history file. Set to -1 for unlimited. Default is 1000.</p>
</td></tr>

<tr><td>
<a if="pyocd_project_dir"><p><code>PYOCD_PROJECT_DIR</code></p></a>
</td><td>
<p>Sets the path to pyOCD's project directory. This variable acts as a fallback if the <code>project_dir</code>
session option is not specified.</p>
</td></tr>

<tr><td>
<a if="pyocd_usb_backend"><p><code>PYOCD_USB_BACKEND</code></p></a>
</td><td>
<p>This variable overrides the default selection of the USB backend for CMSIS-DAP v1 probes. The accepted
values are <code>hidapiusb</code>, <code>pyusb</code>, and <code>pywinusb</code>. An empty value is the same as
unset. CMSIS-DAP v2 probes are unaffected by the environment variable; pyusb is always used.</p>
<p>Forcing the USB backend is really only useful on Windows, because both <code>hidapiusb</code> and
<code>pywinusb</code> backends are available. Note that pyOCD only installs the <code>hidapiusb</code> backend
by default.</p>
</td></tr>

</table>

