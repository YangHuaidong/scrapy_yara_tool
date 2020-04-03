import os

curdir = os.path.dirname(os.path.realpath(__file__))
pass_yara_name = "/home/kevin/Desktop/Arrange_yara/pass_yara_name"

yara_check_meta_key_hash = os.path.join(curdir, "yara_check_meta_key_hash")
new_yara_rules = os.path.join(curdir, "new_yara_rules")


class file_classify():

    def __init__(self):
        pass

    def open_file(self, file_path):
        try:
            for rootpath, dirpath, filenames in os.walk(file_path):
                for filename in filenames:
                    filepath = os.path.join(rootpath, filename)
                    with open(filepath, 'r')as f:
                        f.seek(0)
                        rules = f.read()
                        yield [filename, rules]
        except Exception as e:
            pass

    def pass_yara_name(self, file_path, pass_yara_name, new_yara_rules):
        try:
            for data in self.open_file(file_path):
                if not isinstance(data, list):
                    continue
                with open(pass_yara_name, "r")as f:
                    buf = f.readlines()
                    for i in buf:
                        name = i.strip("\n")
                        if data[0] == name:
                            rule_name = os.path.join(new_yara_rules, data[0]) + ".yar"
                            with open(rule_name, "w")as f:
                                f.write(data[1])
        except Exception as e:
            print(e)


if __name__ == '__main__':
    a = file_classify()
    a.pass_yara_name(yara_check_meta_key_hash, pass_yara_name, new_yara_rules)
