rule CN_Honker_Webshell_ASPX_shell_shell {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file shell.aspx"
    family = "None"
    hacker = "None"
    hash = "1816006827d16ed73cefdd2f11bd4c47c8af43e4"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<%try{ System.Reflection.Assembly.Load(Request.BinaryRead(int.Parse(Request.Cook" ascii /* PEStudio Blacklist: strings */
    $s1 = "<%@ Page Language=\"C#\" ValidateRequest=\"false\" %>" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 1KB and all of them
}