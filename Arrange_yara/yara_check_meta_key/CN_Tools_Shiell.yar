rule CN_Tools_Shiell {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file Shiell.exe"
    family = "None"
    hacker = "None"
    hash = "b432d80c37abe354d344b949c8730929d8f9817a"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "C:\\Users\\Tong\\Documents\\Visual Studio 2012\\Projects\\Shift shell" ascii
    $s2 = "C:\\Windows\\System32\\Shiell.exe" fullword wide
    $s3 = "Shift shell.exe" fullword wide
    $s4 = "\" /v debugger /t REG_SZ /d \"" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 1500KB and 2 of them
}