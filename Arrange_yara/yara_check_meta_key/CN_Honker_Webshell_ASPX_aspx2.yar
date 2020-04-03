rule CN_Honker_Webshell_ASPX_aspx2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file aspx2.txt"
    family = "None"
    hacker = "None"
    hash = "95db7a60f4a9245ffd04c4d9724c2745da55e9fd"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "if (password.Equals(this.txtPass.Text))" fullword ascii /* PEStudio Blacklist: strings */
    $s1 = "<head runat=\"server\">" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = ":<asp:TextBox runat=\"server\" ID=\"txtPass\" Width=\"400px\"></asp:TextBox>" fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "this.lblthispath.Text = Server.MapPath(Request.ServerVariables[\"PATH_INFO\"]);" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x253c and filesize < 9KB and all of them
}