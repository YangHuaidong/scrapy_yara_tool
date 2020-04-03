rule Txt_asp1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-14"
    description = "Chinese Hacktool Set - Webshells - file asp1.txt"
    family = "None"
    hacker = "None"
    hash = "95934d05f0884e09911ea9905c74690ace1ef653"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "if ShellPath=\"\" Then ShellPath = \"cmd.exe\"" fullword ascii
    $s2 = "autoLoginEnable=WSHShell.RegRead(autoLoginPath & autoLoginEnableKey)" fullword ascii
    $s3 = "Set DD=CM.exec(ShellPath&\" /c \"&DefCmd)" fullword ascii
    $s4 = "szTempFile = server.mappath(\"cmd.txt\")" fullword ascii
  condition:
    filesize < 70KB and 2 of them
}