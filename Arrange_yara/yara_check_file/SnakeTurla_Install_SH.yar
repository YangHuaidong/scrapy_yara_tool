rule SnakeTurla_Install_SH {
   meta:
      description = "Detects Snake / Turla Sample"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/QaOh4V"
      date = "2017-05-04"
   strings:
      $s1 = "${TARGET_PATH}/installd.sh" ascii
      $s2 = "$TARGET_PATH2/com.adobe.update.plist" ascii
   condition:
   ( uint16(0) == 0x2123 and filesize < 20KB and all of them )
}