rule BluesPortScan {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Auto-generated rule on file BluesPortScan.exe"
    family = "None"
    hacker = "None"
    hash = "6292f5fc737511f91af5e35643fc9eef"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "This program was made by Volker Voss"
    $s1 = "JiBOo~SSB"
  condition:
    all of them
}