rule RemCom_RemoteCommandExecution {
  meta:
    author = Spider
    comment = None
    date = 2017-12-28
    description = Detects strings from RemCom tool
    family = None
    hacker = None
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://goo.gl/tezXZt
    score = 50
    threatname = RemCom[RemoteCommandExecution
    threattype = RemoteCommandExecution.yar
  strings:
    $ = "\\\\.\\pipe\\%s%s%d"
    $ = "%s\\pipe\\%s%s%d%s"
    $ = "\\ADMIN$\\System32\\%s%s"
  condition:
    1 of them
}