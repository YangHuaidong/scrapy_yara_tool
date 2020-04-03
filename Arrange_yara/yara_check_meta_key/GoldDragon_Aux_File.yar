rule GoldDragon_Aux_File {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-02-03"
    description = "Detects export from Gold Dragon - February 2018"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://securingtomorrow.mcafee.com/mcafee-labs/gold-dragon-widens-olympics-malware-attacks-gains-permanent-presence-on-victims-systems/"
    score = 90
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "/////////////////////regkeyenum////////////" ascii
  condition:
    filesize < 500KB and 1 of them
}