rule FE_LEGALSTRIKE_MACRO {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-06-02"
    description = "This rule is designed to identify macros with the specific encoding used in the sample 30f149479c02b741e897cdb9ecd22da7."
    family = "None"
    filetype = "MACRO"
    hacker = "None"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
    version = ".1"
  strings:
    $ob1 = "ChrW(114) & ChrW(101) & ChrW(103) & ChrW(115) & ChrW(118) & ChrW(114) & ChrW(51) & ChrW(50) & ChrW(46) & ChrW(101)" ascii wide
    $wsobj1 = "Set Obj = CreateObject(\"WScript.Shell\")" ascii wide
    $wsobj2 = "Obj.Run " ascii wide
  condition:
    all of them
}