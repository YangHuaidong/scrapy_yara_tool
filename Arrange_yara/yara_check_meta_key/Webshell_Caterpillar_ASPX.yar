rule Webshell_Caterpillar_ASPX {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/04/03"
    description = "Volatile Cedar Webshell - from file caterpillar.aspx"
    family = "None"
    hacker = "None"
    hash0 = "af4c99208fb92dc42bc98c4f96c3536ec8f3fe56"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://goo.gl/emons5"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Dim objNewRequest As WebRequest = HttpWebRequest.Create(sURL)" fullword
    $s1 = "command = \"ipconfig /all\"" fullword
    $s3 = "For Each xfile In mydir.GetFiles()" fullword
    $s6 = "Dim oScriptNet = Server.CreateObject(\"WSCRIPT.NETWORK\")" fullword
    $s10 = "recResult = adoConn.Execute(strQuery)" fullword
    $s12 = "b = Request.QueryString(\"src\")" fullword
    $s13 = "rw(\"<a href='\" + link + \"' target='\" + target + \"'>\" + title + \"</a>\")" fullword
  condition:
    all of them
}