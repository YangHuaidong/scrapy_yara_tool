rule WebShell_backupsql {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file backupsql.php"
    family = "None"
    hacker = "None"
    hash = "863e017545ec8e16a0df5f420f2d708631020dd4"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "$headers .= \"\\nMIME-Version: 1.0\\n\" .\"Content-Type: multipart/mixed;\\n\" ."
    $s1 = "$ftpconnect = \"ncftpput -u $ftp_user_name -p $ftp_user_pass -d debsender_ftplog"
    $s2 = "* as email attachment, or send to a remote ftp server by" fullword
    $s16 = "* Neagu Mihai<neagumihai@hotmail.com>" fullword
    $s17 = "$from    = \"Neu-Cool@email.com\";  // Who should the emails be sent from?, may "
  condition:
    2 of them
}