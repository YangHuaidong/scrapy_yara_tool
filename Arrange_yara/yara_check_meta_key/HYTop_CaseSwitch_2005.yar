rule HYTop_CaseSwitch_2005 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file 2005.exe"
    family = "None"
    hacker = "None"
    hash = "8bf667ee9e21366bc0bd3491cb614f41"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "MSComDlg.CommonDialog"
    $s2 = "CommonDialog1"
    $s3 = "__vbaExceptHandler"
    $s4 = "EVENT_SINK_Release"
    $s5 = "EVENT_SINK_AddRef"
    $s6 = "By Marcos"
    $s7 = "EVENT_SINK_QueryInterface"
    $s8 = "MethCallEngine"
  condition:
    all of them
}