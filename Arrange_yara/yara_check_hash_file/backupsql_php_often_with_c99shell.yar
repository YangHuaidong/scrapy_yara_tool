rule backupsql_php_often_with_c99shell {
  meta:
    author = Spider
    comment = None
    date = None
    description = Semi-Auto-generated  - file backupsql.php.php.txt
    family = with
    hacker = None
    hash = ab1a06ab1a1fe94e3f3b7f80eedbc12f
    judge = unknown
    reference = None
    threatname = backupsql[php]/often.with.c99shell
    threattype = php
  strings:
    $s2 = "//$message.= \"--{$mime_boundary}\\n\" .\"Content-Type: {$fileatt_type};\\n\" ."
    $s4 = "$ftpconnect = \"ncftpput -u $ftp_user_name -p $ftp_user_pass -d debsender_ftplog"
  condition:
    all of them
}