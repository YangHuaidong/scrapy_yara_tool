rule RemCom_RemoteCommandExecution {
   meta:
      description = "Detects strings from RemCom tool"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/tezXZt"
      date = "2017-12-28"
      score = 50
   strings:
      $ = "\\\\.\\pipe\\%s%s%d"
      $ = "%s\\pipe\\%s%s%d%s"
      $ = "\\ADMIN$\\System32\\%s%s"
   condition:
      1 of them
}