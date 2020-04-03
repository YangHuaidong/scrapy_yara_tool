rule GoldDragon_Aux_File {
   meta:
      description = "Detects export from Gold Dragon - February 2018"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://securingtomorrow.mcafee.com/mcafee-labs/gold-dragon-widens-olympics-malware-attacks-gains-permanent-presence-on-victims-systems/"
      date = "2018-02-03"
      score = 90
   strings:
      $x1 = "/////////////////////regkeyenum////////////" ascii
   condition:
      filesize < 500KB and 1 of them
}