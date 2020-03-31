rule WMI_vbs : APT
{
    meta:
        description = "WMI Tool - APT"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        date = "2013-11-29"
        confidential = false
      score = 70
    strings:
      $s3 = "WScript.Echo \"   $$\\      $$\\ $$\\      $$\\ $$$$$$\\ $$$$$$$$\\ $$\\   $$\\ $$$$$$$$\\  $$$$$$"
    condition:
        all of them
}