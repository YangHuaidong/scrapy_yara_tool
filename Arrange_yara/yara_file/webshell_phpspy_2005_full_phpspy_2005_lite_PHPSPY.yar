rule webshell_phpspy_2005_full_phpspy_2005_lite_PHPSPY {
	meta:
		description = "Web Shell - from files phpspy_2005_full.php, phpspy_2005_lite.php, PHPSPY.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "b68bfafc6059fd26732fa07fb6f7f640"
		hash1 = "42f211cec8032eb0881e87ebdb3d7224"
		hash2 = "0712e3dc262b4e1f98ed25760b206836"
	strings:
		$s6 = "<input type=\"text\" name=\"command\" size=\"60\" value=\"<?=$_POST['comma"
		$s7 = "echo $msg=@copy($_FILES['uploadmyfile']['tmp_name'],\"\".$uploaddir.\"/\".$_FILE"
		$s8 = "<option value=\"passthru\" <? if ($execfunc==\"passthru\") { echo \"selected\"; "
	condition:
		2 of them
}