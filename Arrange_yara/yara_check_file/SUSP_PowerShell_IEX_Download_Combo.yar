rule SUSP_PowerShell_IEX_Download_Combo {
   meta:
      description = "Detects strings found in sample from CN group repo leak in October 2018"
      author = "Florian Roth"
      reference = "https://twitter.com/JaromirHorejsi/status/1047084277920411648"
      date = "2018-10-04"
      hash1 = "13297f64a5f4dd9b08922c18ab100d3a3e6fdeab82f60a4653ab975b8ce393d5"
   strings:
      $x1 = "IEX ((new-object net.webclient).download" ascii nocase
      $fp = "Remote Desktop in the Appveyor" ascii
   condition:
      $x1 and not 1 of ($fp*)
}