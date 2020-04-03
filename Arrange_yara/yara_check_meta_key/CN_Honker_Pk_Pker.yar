rule CN_Honker_Pk_Pker {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file Pker.exe"
    family = "None"
    hacker = "None"
    hash = "631787f27f27c46f79e58e1accfcc9ecfb4d3a2f"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "/msadc/..%5c..%5c..%5c..%5cwinnt/system32/cmd.exe" fullword wide /* PEStudio Blacklist: strings */
    $s2 = "msadc/..\\..\\..\\..\\winnt/system32/cmd.exe" fullword wide /* PEStudio Blacklist: strings */
    $s3 = "--Made by VerKey&Only_Guest&Bincker" fullword wide /* PEStudio Blacklist: strings */
    $s4 = ";APPLET;EMBED;FRAMESET;HEAD;NOFRAMES;NOSCRIPT;OBJECT;SCRIPT;STYLE;" fullword wide /* PEStudio Blacklist: strings */
    $s5 = " --Welcome to Www.Pker.In Made by V.K" fullword wide
    $s6 = "Report.dat" fullword wide /* PEStudio Blacklist: strings */
    $s7 = ".\\Report.dat" fullword wide /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 500KB and 5 of them
}