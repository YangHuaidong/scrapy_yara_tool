rule PHP_Webshell_1_Feb17 {
   meta:
      description = "Detects a simple cloaked PHP web shell"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://isc.sans.edu/diary/Analysis+of+a+Simple+PHP+Backdoor/22127"
      date = "2017-02-28"
   strings:
      $h1 = "<?php ${\"\\x" ascii
      $x1 = "\";global$auth;function sh_decrypt_phase($data,$key){${\"" ascii
      $x2 = "global$auth;return sh_decrypt_phase(sh_decrypt_phase($" ascii
      $x3 = "]}[\"\x64\"]);}}echo " ascii
      $x4 = "\"=>@phpversion(),\"\\x" ascii
      /* Decloaked version */
      $s1 = "$i=Array(\"pv\"=>@phpversion(),\"sv\"" ascii
      $s3 = "$data = @unserialize(sh_decrypt(@base64_decode($data),$data_key));" ascii
   condition:
      uint32(0) == 0x68703f3c and ( $h1 at 0 and 1 of them ) or 2 of them
}