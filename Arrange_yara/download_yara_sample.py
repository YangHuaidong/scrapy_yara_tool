import requests

url = 'https://www.virustotal.com/vtapi/v2/file/download'

hash_name = "/home/kevin/Desktop/Arrange_yara/hash_name"


def download_yara():
    # with open(hash_name, 'r')as f:
    #     f.seek(0)
    #     line = f.readlines()
    #     for y in line:
    #         i = y.split()[0]
    i = "cabf47b96e3b2c46248f075bdbc46197db28a25f"
    params = {'apikey': 'b1637ab04a2f725d6a852f61c8531a64b2248c4438fd120abd3cb08196235af6', 'hash': i}
    response = requests.get(url, params=params)
    downloaded_file = response.content
    with open(i, "a+")as f:
        f.write(downloaded_file)

if __name__ == '__main__':
    download_yara()