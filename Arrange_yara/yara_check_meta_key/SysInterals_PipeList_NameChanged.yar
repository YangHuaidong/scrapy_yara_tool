rule SysInterals_PipeList_NameChanged {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-06-04"
    description = "Detects NirSoft PipeList"
    family = "None"
    hacker = "None"
    hash1 = "83f0352c14fa62ae159ab532d85a2b481900fed50d32cc757aa3f4ccf6a13bee"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/Mr6M2J"
    score = 90
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "PipeList" ascii fullword
    $s2 = "Sysinternals License" ascii fullword
  condition:
    uint16(0) == 0x5a4d and filesize < 170KB and all of them
    and not filename contains "pipelist.exe"
    and not filename contains "PipeList.exe"
}