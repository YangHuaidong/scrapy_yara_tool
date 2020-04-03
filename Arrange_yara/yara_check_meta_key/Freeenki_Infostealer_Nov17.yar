rule Freeenki_Infostealer_Nov17 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-11-28"
    description = "Detects Freenki infostealer malware"
    family = "None"
    hacker = "None"
    hash1 = "99c1b4887d96cb94f32b280c1039b3a7e39ad996859ffa6dd011cf3cca4f1ba5"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://blog.talosintelligence.com/2017/11/ROKRAT-Reloaded.html"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "base64Encoded=\"TVqQAAMAAAAEAAAA" ascii
    $x2 = "command =outFile &\" sysupdate\"" fullword ascii
    $x3 = "outFile=sysDir&\"\\rundll32.exe\"" fullword ascii
    $s1 = "SOFTWARE\\Clients\\StartMenuInternet\\firefox.exe\\shell\\open\\command" fullword wide
    $s2 = "c:\\TEMP\\CrashReports\\" fullword ascii
    $s3 = "objShell.run command, 0, True" fullword ascii
    $s4 = "sysDir = shell.ExpandEnvironmentStrings(\"%windir%\")" fullword ascii
    $s5 = "'Wscript.echo \"Base64 encoded: \" + base64Encoded" fullword ascii
    $s6 = "set shell = WScript.CreateObject(\"WScript.Shell\")" fullword ascii
    $a1 = "\\Google\\Chrome\\User Data\\Default\\Login Data" fullword ascii
    $a2 = "SELECT username_value, password_value, signon_realm FROM logins" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 3000KB and (
    1 of ($x*) or
    3 of them or
    all of ($a*)
}