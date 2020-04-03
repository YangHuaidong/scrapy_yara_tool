rule GoldenEye_Ransomware_XLS {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-12-06"
    description = "GoldenEye XLS with Macro - file Schneider-Bewerbung.xls"
    family = "None"
    hacker = "None"
    hash1 = "2320d4232ee80cc90bacd768ba52374a21d0773c39895b88cdcaa7782e16c441"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/jp2SkT"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "fso.GetTempName();tmp_path = tmp_path.replace('.tmp', '.exe')" fullword ascii
    $x2 = "var shell = new ActiveXObject('WScript.Shell');shell.run(t'" fullword ascii
  condition:
    ( uint16(0) == 0xcfd0 and filesize < 4000KB and 1 of them )
}