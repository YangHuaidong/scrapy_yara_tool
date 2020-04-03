rule uploader_php_php {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file uploader.php.php.txt"
    family = "None"
    hacker = "None"
    hash = "0b53b67bb3b004a8681e1458dd1895d0"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "move_uploaded_file($userfile, \"entrika.php\"); " fullword
    $s3 = "Send this file: <INPUT NAME=\"userfile\" TYPE=\"file\">" fullword
    $s4 = "<INPUT TYPE=\"hidden\" name=\"MAX_FILE_SIZE\" value=\"100000\">" fullword
  condition:
    2 of them
}