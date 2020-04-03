rule Gen_Net_LocalGroup_Administrators_Add_Command {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-07-08"
    description = "Detects an executable that contains a command to add a user account to the local administrators group"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = /net localgroup administrators [a-zA-Z0-9]{1,16} \/add/ nocase ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 400KB and 1 of them )
}