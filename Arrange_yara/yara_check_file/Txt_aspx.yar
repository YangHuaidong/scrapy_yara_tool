rule Txt_aspx {
  meta:
    author = Spider
    comment = None
    date = 2015-06-14
    description = Chinese Hacktool Set - Webshells - file aspx.jpg
    family = None
    hacker = None
    hash = ce24e277746c317d887139a0d71dd250bfb0ed58
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://tools.zjqhr.com/
    threatname = Txt[aspx
    threattype = aspx.yar
  strings:
    $s1 = "SQLExec : <asp:DropDownList runat=\"server\" ID=\"FGEy\" AutoPostBack=\"True\" O" ascii
    $s2 = "Process[] p=Process.GetProcesses();" fullword ascii
    $s3 = "Copyright &copy; 2009 Bin" ascii
    $s4 = "<td colspan=\"5\">CmdShell&nbsp;&nbsp;:&nbsp;<input class=\"input\" runat=\"serv" ascii
  condition:
    filesize < 100KB and all of them
}