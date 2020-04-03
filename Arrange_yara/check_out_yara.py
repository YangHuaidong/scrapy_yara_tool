import os
import yara

# file_path = "/home/kevin/Desktop/Arrange_yara/APT_NK_BabyShark_KimJoingRAT_Apr19_1"
# black_sample = "/home/kevin/Desktop/Arrange_yara/d50a0980da6297b8e4cec5db0a8773635cee74ac6f5c1ff18197dfba549f6712"
#
# rule = yara.compile(filepath=file_path)
# with open(black_sample, "rb")as f:
#     a = f.read()
# matches = rule.match(data=a)

# print(matches)
# print(matches[0])
# if matches[0].strings != -1:
# print(111)
# else:
# print(222)
# print(matches[0].strings)


import yaratool

yara_check_meta_key_hash = "/home/kevin/Desktop/Arrange_yara/yara_check_meta_key_hash"
sample_file_path = "/home/kevin/Desktop/Arrange_yara/file_sample"

pass_yara_name = "/home/kevin/Desktop/Arrange_yara/pass_yara_name"
no_pass_yara_name = "/home/kevin/Desktop/Arrange_yara/no_pass_yara_name"


class Check_Yara():

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
                        yield [filepath, rules]
        except Exception as e:
            pass

    def check_batch_yara(self, yara_check_meta_key_hash, sample_file_path, pass_yara_name):
        try:
            pass_yara_ = []
            for rules in self.open_file(yara_check_meta_key_hash):
                if not isinstance(rules, list):
                    continue
                try:
                    yr = yaratool.YaraRule(rules[1])
                    for k in ["hash", "hash1"]:
                        if k not in yr.metas.keys():
                            continue
                        try:
                            check_rule = yara.compile(filepath=rules[0])
                            for rootpath, dirpath, filenames in os.walk(sample_file_path):
                                for filename in filenames:
                                    if filename == yr.metas[k]:
                                        filepath = os.path.join(rootpath, filename)
                                        with open(filepath, 'rb')as f:
                                            try:
                                                matches = check_rule.match(data=f.read())
                                                if matches[0].strings != -1:
                                                    pass_yara_.append(yr.name)
                                                    # with open(pass_yara_name, "a+")as ft:
                                                    #     ft.write(yr.name + "\n")
                                            except Exception as e:
                                                print(e)
                        except Exception as e:
                            print(e)
                except Exception as e:
                    print(e)
            with open(pass_yara_name, "w")as ft:
                for i in pass_yara_:
                    ft.write(i + "\n")
        except Exception as e:
            print(e)


if __name__ == '__main__':
    a = Check_Yara()
    a.check_batch_yara(yara_check_meta_key_hash, sample_file_path, pass_yara_name)
