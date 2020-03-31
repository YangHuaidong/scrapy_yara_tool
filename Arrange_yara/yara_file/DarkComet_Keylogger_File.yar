rule DarkComet_Keylogger_File
{
   meta:
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      description = "Looks like a keylogger file created by DarkComet Malware"
      date = "25.07.14"
      score = 50
   strings:
      $entry = /\n:: [A-Z]/
      $timestamp = /\([0-9]?[0-9]:[0-9][0-9]:[0-9][0-9] [AP]M\)/
   condition:
      uint16(0) == 0x3A3A and #entry > 10 and #timestamp > 10
}