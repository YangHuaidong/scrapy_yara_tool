rule Buckeye_Osinfo {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-09-05"
    description = "Detects OSinfo tool used by the Buckeye APT group"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://www.symantec.com/connect/blogs/buckeye-cyberespionage-group-shifts-gaze-us-hong-kong"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "-s ShareInfo ShareDir" fullword ascii
    $s2 = "-a Local And Global Group User Info" fullword ascii
    $s3 = "-f <infile> //input server list from infile, OneServerOneLine" fullword ascii
    $s4 = "info <\\server> <user>" fullword ascii
    $s5 = "-c Connect Test" fullword ascii
    $s6 = "-gd Group Domain Admins" fullword ascii
    $s7 = "-n NetuseInfo" fullword ascii
  condition:
    uint16(0) == 0x5a4d and 3 of ($s*)
}