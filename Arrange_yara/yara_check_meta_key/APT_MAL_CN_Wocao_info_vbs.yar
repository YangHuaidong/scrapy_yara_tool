rule APT_MAL_CN_Wocao_info_vbs {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Strings from the information grabber VBS"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
    threatname = "None"
    threattype = "None"
  strings:
    $ = "Logger PingConnect"
    $ = "Logger GetAdmins"
    $ = "Logger InstallPro"
    $ = "Logger Exec"
    $ = "retstr = adminsName & \" Members\" & vbCrLf & _"
    $ = "Logger VolumeName & \" (\" & objDrive.DriveLetter & \":)\" _"
    $ = "txtRes = txtRes & machine & \" can"
    $ = "retstr = \"PID   SID Image Name\" & vbCrLf & \"===="
  condition:
    4 of them
}