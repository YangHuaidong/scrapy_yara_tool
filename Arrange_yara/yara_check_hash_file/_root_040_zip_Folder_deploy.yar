rule _root_040_zip_Folder_deploy {
  meta:
    author = Spider
    comment = None
    date = None
    description = Webshells Auto-generated - file deploy.exe
    family = zip
    hacker = None
    hash = 2c9f9c58999256c73a5ebdb10a9be269
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = [root]/040.zip.Folder.deploy
    threattype = root
  strings:
    $s5 = "halon synscan 127.0.0.1 1-65536"
    $s8 = "Obviously you replace the ip address with that of the target."
  condition:
    all of them
}