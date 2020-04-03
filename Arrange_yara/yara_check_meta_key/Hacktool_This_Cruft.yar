rule Hacktool_This_Cruft {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-08-08"
    description = "Detects string 'This cruft' often used in hack tools like netcat or cryptcat and also mentioned in Project Sauron report"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/eFoP4A"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "This cruft" fullword
  condition:
    ( uint16(0) == 0x5a4d and filesize < 200KB and $x1 )
}