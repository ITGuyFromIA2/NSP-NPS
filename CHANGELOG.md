# Changelog

All notable changes to NSP.NPS are documented here. Versions follow
[SemVer](https://semver.org/). `0.x` until it has real use outside NSP.

## 0.1.1

- Menu 7 (hand back) opens the output folder in Explorer after writing <Company>_NPS_Response.json,
  so the tech can copy it off the server (accept the access prompt - the folder is
  Administrators-only).

## 0.1.0

First release.

The other NSP modules it needs are installed from the PowerShell Gallery the first time they're needed,
so `Install-Module` of this one module is enough. Set `NSP_NO_AUTOINSTALL=1` to turn that off.
