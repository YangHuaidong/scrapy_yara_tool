rule rst_sql_php_php {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file rst_sql.php.php.txt"
    family = "None"
    hacker = "None"
    hash = "0961641a4ab2b8cb4d2beca593a92010"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "C:\\tmp\\dump_"
    $s1 = "RST MySQL"
    $s2 = "http://rst.void.ru"
    $s3 = "$st_form_bg='R0lGODlhCQAJAIAAAOfo6u7w8yH5BAAAAAAALAAAAAAJAAkAAAIPjAOnuJfNHJh0qtfw0lcVADs=';"
  condition:
    2 of them
}