rule Keylogger_CN_APT {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-03-07"
    description = "Keylogger - generic rule for a Chinese variant"
    family = "None"
    hacker = "None"
    hash = "3efb3b5be39489f19d83af869f11a8ef8e9a09c3c7c0ad84da31fc45afcf06e7"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 75
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "Mozilla/4.0 (compatible; MSIE6.0;Windows NT 5.1)" fullword ascii
    $x2 = "attrib -s -h -r c:\\ntldr" fullword ascii
    $x3 = "%sWindows NT %d.%d" fullword ascii
    $x4 = "Referer: http://%s/%s.aspx?n=" fullword ascii
    $s1 = "\\cmd.exe /c \"systeminfo.exe >> " fullword ascii
    $s2 = "%s\\cmd.exe /c %s >> \"%s\"" fullword ascii
    $s3 = "shutdown.exe -r -t 0" fullword ascii
    $s4 = "dir \"%SystemDrive%\\\" /s /a" fullword ascii
    $s5 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;" fullword ascii
    $s6 = "http_s.exe" fullword ascii
    $s7 = "User Agent\\Post Platform\\" fullword ascii
    $s8 = "desktop.tmp" fullword ascii
    $s9 = "\\support.icw" fullword ascii
    $s10 = "agc.tmp" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 100KB and 1 of ($x*) ) or 3 of them
}