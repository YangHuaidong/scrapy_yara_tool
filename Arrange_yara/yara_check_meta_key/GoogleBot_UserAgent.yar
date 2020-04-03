rule GoogleBot_UserAgent {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-01-27"
    description = "Detects the GoogleBot UserAgent String in an Executable"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    score = 65
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" fullword ascii
    $fp1 = "McAfee, Inc." wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 500KB and $x1 and not 1 of ($fp*) )
}