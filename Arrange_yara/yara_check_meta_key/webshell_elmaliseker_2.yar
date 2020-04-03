rule webshell_elmaliseker_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file elmaliseker.asp"
    family = "None"
    hacker = "None"
    hash = "b32d1730d23a660fd6aa8e60c3dc549f"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "<td<%if (FSO.GetExtensionName(path & \"\\\" & oFile.Name)=\"lnk\") or (FSO.GetEx"
    $s6 = "<input type=button value=Save onclick=\"EditorCommand('Save')\"> <input type=but"
  condition:
    all of them
}