rule WMI_vbs : APT {
  meta:
    author = "Spider"
    comment = "None"
    confidential = false
    date = "2013-11-29"
    description = "WMI Tool - APT"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s3 = "WScript.Echo \"   $$\\      $$\\ $$\\      $$\\ $$$$$$\\ $$$$$$$$\\ $$\\   $$\\ $$$$$$$$\\  $$$$$$"
  condition:
    all of them
}