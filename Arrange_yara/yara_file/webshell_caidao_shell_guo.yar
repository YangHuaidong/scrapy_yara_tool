rule webshell_caidao_shell_guo {
	meta:
		description = "Web Shell - file guo.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "9e69a8f499c660ee0b4796af14dc08f0"
	strings:
		$s0 = "<?php ($www= $_POST['ice'])!"
		$s1 = "@preg_replace('/ad/e','@'.str_rot13('riny').'($ww"
	condition:
		1 of them
}