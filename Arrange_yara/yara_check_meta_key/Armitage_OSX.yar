rule Armitage_OSX {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-12-24"
    description = "Detects Armitage component"
    family = "None"
    hacker = "None"
    hash1 = "2680d9900a057d553fcb28d84cdc41c3fc18fd224a88a32ee14c9c1b501a86af"
    hash2 = "b7b506f38d0553cd2beb4111c7ef383c821f04cee5169fed2ef5d869c9fbfab3"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "resources/covertvpn-injector.exe" fullword ascii
    $s10 = "resources/browserpivot.x64.dll" fullword ascii
    $s17 = "resources/msfrpcd_new.bat" fullword ascii
  condition:
    filesize < 6000KB and 1 of them
}