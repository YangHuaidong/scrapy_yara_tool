rule Certutil_Decode_OR_Download {
  meta:
    author = Spider
    comment = None
    date = 2017-08-29
    description = Certutil Decode
    family = Download
    hacker = None
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = Internal Research
    score = 40
    threatname = Certutil[Decode]/OR.Download
    threattype = Decode
  strings:
    $a1 = "certutil -decode " ascii wide
    $a2 = "certutil  -decode " ascii wide
    $a3 = "certutil.exe -decode " ascii wide
    $a4 = "certutil.exe  -decode " ascii wide
    $a5 = "certutil -urlcache -split -f http" ascii wide
    $a6 = "certutil.exe -urlcache -split -f http" ascii wide
  condition:
    ( not MSI and filesize < 700KB and 1 of them )
}