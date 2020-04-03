rule XYZCmd_zip_Folder_XYZCmd {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file XYZCmd.exe"
    family = "None"
    hacker = "None"
    hash = "bbea5a94950b0e8aab4a12ad80e09b630dd98115"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Executes Command Remotely" fullword wide
    $s2 = "XYZCmd.exe" fullword wide
    $s6 = "No Client Software" fullword wide
    $s19 = "XYZCmd V1.0 For NT S" fullword ascii
  condition:
    all of them
}