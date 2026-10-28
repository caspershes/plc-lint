# Reading the CODESYS `.export` format

Notes for anyone who wants to parse the format themselves, or who wonders why the
analyser treats an export differently from a PLCopenXML file. None of this is needed
to *use* the tool — see the [README](../README.md) for that.

## How a program is stored

In an export a POU body is stored line by line, and the declarations sit in a separate
section. The parser rebuilds them into a PLCopenXML-shaped tree and hands that tree to
the usual analyser — one rule set, one set of texts, no second engine to drift apart.
The format is detected by content, not by extension.

Parsing is streaming, with subtree clearing: a 29 MB export costs about 47 MB of memory
instead of the 204 MB a full tree would take, and a live project comes out as 25 POUs
and 205 globals in roughly two seconds.

## Three things that cost time

1. **The same device parameter can appear three times** — the template from the device
   description, an internal copy, and only the last one is the actual configuration.
   Take the **last** occurrence. Reading the first one made an earlier tool report
   "sensor type not selected" three times on a project that had Pt1000 configured.
2. **The enum value of a parameter is not in the parameter itself**, it is one level
   down in `BaseType/Value`. Without that, a channel shows only its `FilterTime` and
   the sensor type goes unnoticed.
3. **A channel counts as used when a variable is bound to `SensorValueN.SensorValue`**,
   not by `InputStatus`. Status codes are deliberately bound on spare inputs too, so
   `InputStatus` is a bad indicator of occupancy.

For visualisation elements there is a fourth: an element has nested sub-elements with
property lists of their own, so only the direct children count. Otherwise geometry and
captions from different elements merge.

## What the export adds to the analysis

Screen bindings and unit-conversion objects count as uses, so a setpoint that lives
only on a screen is no longer reported as dead — on a live project the whole weather
curve is built from unit-conversion objects and never appears in ST. The same data
turns "nothing writes this alarm" from a guess into a fact, which is why that finding
is raised to critical on `.export` and stays a warning on PLCopenXML.

## What it does not give

The task configuration is laid out differently there, so the watchdog and
duplicate-Modbus-address rules stay silent on an export. Run the PLCopenXML export too
if you need those.
