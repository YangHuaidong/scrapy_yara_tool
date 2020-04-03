rule webshell_shell_phpspy_2006_arabicspy_hkrkoz {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - from files shell.php, phpspy_2006.php, arabicspy.php, hkrkoz.php"
    family = "None"
    hacker = "None"
    hash0 = "791708057d8b429d91357d38edf43cc0"
    hash1 = "40a1f840111996ff7200d18968e42cfe"
    hash2 = "e0202adff532b28ef1ba206cf95962f2"
    hash3 = "802f5cae46d394b297482fd0c27cb2fc"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s5 = "$prog = isset($_POST['prog']) ? $_POST['prog'] : \"/c net start > \".$pathname."
  condition:
    all of them
}