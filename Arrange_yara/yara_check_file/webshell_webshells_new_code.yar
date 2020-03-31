rule webshell_webshells_new_code {
  meta:
    author = Spider
    comment = None
    date = 2014/03/28
    description = Web shells - generated from file code.php
    family = code
    hacker = None
    hash = a444014c134ff24c0be5a05c02b81a79
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    threatname = webshell[webshells]/new.code
    threattype = webshells
  strings:
    $s1 = "<a class=\"high2\" href=\"javascript:;;;\" name=\"action=show&dir=$_ipage_fi"
    $s7 = "$file = !empty($_POST[\"dir\"]) ? urldecode(self::convert_to_utf8(rtrim($_PO"
    $s10 = "if (true==@move_uploaded_file($_FILES['userfile']['tmp_name'],self::convert_"
    $s14 = "Processed in <span id=\"runtime\"></span> second(s) {gzip} usage:"
    $s17 = "<a href=\"javascript:;;;\" name=\"{return_link}\" onclick=\"fileperm"
  condition:
    1 of them
}