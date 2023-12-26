# Drupalgeddon2 Remote Code Execution
## Description

In march 2018, a critical vulnerability was discovered on Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1, which allowed to remote attackers the execution of arbitrary code, with a CVE identifier of [CVE-2018-7600](https://nvd.nist.gov/vuln/detail/cve-2018-7600).


## Installation

```
git clone https://github.com/ret2x-tools/drupalgeddon2-rce.git
pip install -r requirements.txt
```


## Usage

```
root@parrot:~# python3 poc.py -h
usage: poc.py [-h] -u URL

Drupalgeddon2 RCE on Drupal <= 7.57

optional arguments:
  -h, --help         show this help message and exit
  -u URL, --url URL  Target url
```


## References

[https://nvd.nist.gov/vuln/detail/cve-2018-7600](https://nvd.nist.gov/vuln/detail/cve-2018-7600)

[https://ine.com/blog/cve-2018-7600-drupalgeddon-2](https://ine.com/blog/cve-2018-7600-drupalgeddon-2)
