rule aspfile1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file aspfile1.asp"
    family = "None"
    hacker = "None"
    hash = "77b1e3a6e8f67bd6d16b7ace73dca383725ac0af"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "' -- check for a command that we have posted -- '" fullword ascii
    $s1 = "szTempFile = \"C:\\\" & oFileSys.GetTempName( )" fullword ascii
    $s5 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=gb2312\"><BODY>" fullword ascii
    $s6 = "<input type=text name=\".CMD\" size=45 value=\"<%= szCMD %>\">" fullword ascii
    $s8 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword ascii
    $s15 = "szCMD = Request.Form(\".CMD\")" fullword ascii
  condition:
    3 of them
}