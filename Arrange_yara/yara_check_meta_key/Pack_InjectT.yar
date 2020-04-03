rule Pack_InjectT {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file InjectT.exe"
    family = "None"
    hacker = "None"
    hash = "983b74ccd57f6195a0584cdfb27d55e8"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s3 = "ail To Open Registry"
    $s4 = "32fDssignim"
    $s5 = "vide Internet S"
    $s6 = "d]Software\\M"
    $s7 = "TInject.Dll"
  condition:
    all of them
}