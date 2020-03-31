rule Nishang_Webshell {
  meta:
    author = Spider
    comment = None
    date = 2016-09-11
    description = Detects a ASPX web shell
    family = None
    hacker = None
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://github.com/samratashok/nishang
    threatname = Nishang[Webshell
    threattype = Webshell.yar
  strings:
    $s1 = "psi.Arguments = \"-noninteractive \" + \"-executionpolicy bypass \" + arg;" ascii
    $s2 = "output.Text += \"\nPS> \" + console.Text + \"\n\" + do_ps(console.Text);" ascii
    $s3 = "<title>Antak Webshell</title>" fullword ascii
    $s4 = "<asp:Button ID=\"executesql\" runat=\"server\" Text=\"Execute SQL Query\"" ascii
  condition:
    ( uint16(0) == 0x253C and filesize < 100KB and 1 of ($s*) )
}