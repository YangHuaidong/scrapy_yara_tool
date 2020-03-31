rule WMI_vbs : APT {
  meta:
    author = Spider
    comment = None
    confidential = false
    date = 2013-11-29
    description = WMI Tool - APT
    family = None
    hacker = None
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    threatname = WMI[vbs
    threattype = vbs.yar
  strings:
    $s3 = "WScript.Echo \"   $$\\      $$\\ $$\\      $$\\ $$$$$$\\ $$$$$$$$\\ $$\\   $$\\ $$$$$$$$\\  $$$$$$"
  condition:
    all of them
}