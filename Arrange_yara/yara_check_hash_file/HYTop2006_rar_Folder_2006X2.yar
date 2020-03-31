rule HYTop2006_rar_Folder_2006X2 {
  meta:
    author = Spider
    comment = None
    date = None
    description = Webshells Auto-generated - file 2006X2.exe
    family = 2006X2
    hacker = None
    hash = cc5bf9fc56d404ebbc492855393d7620
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = HYTop2006[rar]/Folder.2006X2
    threattype = rar
  strings:
    $s2 = "Powered By "
    $s3 = " \" onClick=\"this.form.sharp.name=this.form.password.value;this.form.action=this."
  condition:
    all of them
}