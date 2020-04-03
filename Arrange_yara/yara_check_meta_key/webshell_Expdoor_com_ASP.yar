rule webshell_Expdoor_com_ASP {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/03/28"
    description = "Web shells - generated from file Expdoor.com ASP.asp"
    family = "None"
    hacker = "None"
    hash = "caef01bb8906d909f24d1fa109ea18a7"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s4 = "\">www.Expdoor.com</a>" fullword
    $s5 = "    <input name=\"FileName\" type=\"text\" value=\"Asp_ver.Asp\" size=\"20\" max"
    $s10 = "set file=fs.OpenTextFile(server.MapPath(FileName),8,True)  '" fullword
    $s14 = "set fs=server.CreateObject(\"Scripting.FileSystemObject\")   '" fullword
    $s16 = "<TITLE>Expdoor.com ASP" fullword
  condition:
    2 of them
}