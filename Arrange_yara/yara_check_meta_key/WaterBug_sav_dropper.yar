import "pe"
rule WaterBug_sav_dropper {
  meta:
    author = "Spider"
    comment = "None"
    date = "22.01.2015"
    description = "Symantec Waterbug Attack - SAV Dropper"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "http://t.co/rF35OaAXrl"
    threatname = "None"
    threattype = "None"
  strings:
    $mz = "MZ"
    $a = /[a-z]{,10}_x64.sys\x00hMZ\x00/
  condition:
    ($mz at 0) and uint32(0x400) == 0x000000c3 and pe.number_of_sections == 6 and $a
}