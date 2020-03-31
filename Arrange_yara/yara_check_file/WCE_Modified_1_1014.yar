rule WCE_Modified_1_1014 {
  meta:
    author = Spider
    comment = None
    date = None
    description = Modified (packed) version of Windows Credential Editor
    family = 1014
    hacker = None
    hash = 09a412ac3c85cedce2642a19e99d8f903a2e0354
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    threatname = WCE[Modified]/1.1014
    threattype = Modified
  strings:
    $s0 = "LSASS.EXE" fullword ascii
    $s1 = "_CREDS" ascii
    $s9 = "Using WCE " ascii
  condition:
    all of them
}