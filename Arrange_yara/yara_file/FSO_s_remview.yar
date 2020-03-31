rule FSO_s_remview {
	meta:
		description = "Webshells Auto-generated - file remview.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "b4a09911a5b23e00b55abe546ded691c"
	strings:
		$s2 = "      echo \"<hr size=1 noshade>\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\""
		$s3 = "         echo \"<script>str$i=\\\"\".str_replace(\"\\\"\",\"\\\\\\\"\",str_replace(\"\\\\\",\"\\\\\\\\\""
		$s4 = "      echo \"<hr size=1 noshade>\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n<"
	condition:
		all of them
}