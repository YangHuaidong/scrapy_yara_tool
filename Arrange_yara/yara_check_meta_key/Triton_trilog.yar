rule Triton_trilog {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-12-14"
    description = "Detects Triton APT malware - file trilog.exe"
    family = "None"
    hacker = "None"
    hash1 = "e8542c07b2af63ee7e72ce5d97d91036c5da56e2b091aa2afe737b224305d230"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/vtQoCQ"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "inject.bin" ascii
    $s2 = "PYTHON27.DLL" fullword ascii
    $s3 = "payload" ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 60KB and all of them
}