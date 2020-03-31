rule FeliksPack3___PHP_Shells_xIShell {
	meta:
		description = "Webshells Auto-generated - file xIShell.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "997c8437c0621b4b753a546a53a88674"
	strings:
		$s3 = "if (!$nix) { $xid = implode(explode(\"\\\\\",$xid),\"\\\\\\\\\");}echo (\"<td><a href='Java"
	condition:
		all of them
}