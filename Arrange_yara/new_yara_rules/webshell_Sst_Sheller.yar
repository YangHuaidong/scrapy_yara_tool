rule webshell_Sst_Sheller {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file Sst-Sheller.php"
    family = "None"
    hacker = "None"
    hash = "d93c62a0a042252f7531d8632511ca56"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "echo \"<a href='?page=filemanager&id=fm&fchmod=$dir$file'>"
    $s3 = "<? unlink($filename); unlink($filename1); unlink($filename2); unlink($filename3)"
  condition:
    all of them
}