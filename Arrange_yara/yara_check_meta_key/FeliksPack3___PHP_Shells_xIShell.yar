rule FeliksPack3___PHP_Shells_xIShell {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file xIShell.php"
    family = "None"
    hacker = "None"
    hash = "997c8437c0621b4b753a546a53a88674"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s3 = "if (!$nix) { $xid = implode(explode(\"\\\\\",$xid),\"\\\\\\\\\");}echo (\"<td><a href='Java"
  condition:
    all of them
}