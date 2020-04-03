rule CN_Honker_Webshell_ASPX_aspx4 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file aspx4.txt"
    family = "None"
    hacker = "None"
    hash = "200a8f15ffb6e3af31d28c55588003b5025497eb"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s4 = "File.Delete(cdir.FullName + \"\\\\test\");" fullword ascii /* PEStudio Blacklist: strings */
    $s5 = "start<asp:TextBox ID=\"Fport_TextBox\" runat=\"server\" Text=\"c:\\\" Width=\"60" ascii /* PEStudio Blacklist: strings */
    $s6 = "<div>Code By <a href =\"http://www.hkmjj.com\">Www.hkmjj.Com</a></div>" fullword ascii
  condition:
    filesize < 11KB and all of them
}