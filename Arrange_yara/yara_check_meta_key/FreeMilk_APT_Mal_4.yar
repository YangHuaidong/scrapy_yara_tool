import "pe"
rule FreeMilk_APT_Mal_4 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-10-05"
    description = "Detects malware from FreeMilk campaign"
    family = "None"
    hacker = "None"
    hash1 = "99c1b4887d96cb94f32b280c1039b3a7e39ad996859ffa6dd011cf3cca4f1ba5"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://researchcenter.paloaltonetworks.com/2017/10/unit42-freemilk-highly-targeted-spear-phishing-campaign/"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "base64Encoded=\"TVqQAAMAAAAE" ascii
    $s1 = "SOFTWARE\\Clients\\StartMenuInternet\\firefox.exe\\shell\\open\\command" fullword wide
    $s2 = "'Wscript.echo \"Base64 encoded: \" + base64Encoded" fullword ascii
    $s3 = "\\Google\\Chrome\\User Data\\Default\\Login Data" fullword ascii
    $s4 = "outFile=sysDir&\"\\rundll32.exe\"" fullword ascii
    $s5 = "set shell = WScript.CreateObject(\"WScript.Shell\")" fullword ascii
    $s6 = "command =outFile &\" sysupdate\"" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 3000KB and (
    ( pe.exports("getUpdate") and pe.number_of_exports == 1 ) or
    1 of ($x*) or
    3 of them
}