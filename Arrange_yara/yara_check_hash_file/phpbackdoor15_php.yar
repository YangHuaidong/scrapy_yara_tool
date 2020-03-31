rule phpbackdoor15_php {
  meta:
    author = Spider
    comment = None
    date = None
    description = Semi-Auto-generated  - file phpbackdoor15.php.txt
    family = None
    hacker = None
    hash = 0fdb401a49fc2e481e3dfd697078334b
    judge = unknown
    reference = None
    threatname = phpbackdoor15[php
    threattype = php.yar
  strings:
    $s1 = "echo \"fichier telecharge dans \".good_link(\"./\".$_FILES[\"fic\"][\"na"
    $s2 = "if(move_uploaded_file($_FILES[\"fic\"][\"tmp_name\"],good_link(\"./\".$_FI"
    $s3 = "echo \"Cliquez sur un nom de fichier pour lancer son telechargement. Cliquez s"
  condition:
    1 of them
}