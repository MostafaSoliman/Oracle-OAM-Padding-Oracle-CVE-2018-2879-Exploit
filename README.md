# Oracle-OAM-Padding-Oracle-CVE-2018-2879-Exploit

### Introduction
This exploit was developed during pentesting activity against oracle OAM 11.1.2.3.0. It was developed based on the technical description by sec-consult
```
https://www.sec-consult.com/en/blog/2018/05/oracle-access-managers-identity-crisis/
```

### Requirments
The exploit depend on python-paddingoracle it can be downloaded from here
```
https://github.com/mwielgoszewski/python-paddingoracle
```
### How the exploit works
```
# python oracle-oam-exploit.py -h

#######    #    #     #    #######
#     #   # #   ##   ##    #       #    # #####  #       ####  # #####
#     #  #   #  # # # #    #        #  #  #    # #      #    # #   #
#     # #     # #  #  #    #####     ##   #    # #      #    # #   #
#     # ####### #     #    #         ##   #####  #      #    # #   #
#     # #     # #     #    #        #  #  #      #      #    # #   #
####### #     # #     #    ####### #    # #      ######  ####  #   #
Oracle Padding Oracle
                                coded by: Mostafa Soliman

usage: oracle-oam-exploit.py [-h] [-e ENCRYPT] [-d DECRYPT] [-v] URL

positional arguments:
  URL                   Target resource URL

optional arguments:
  -h, --help            show this help message and exit
  -e ENCRYPT, --encrypt ENCRYPT
                        Encrypt plain text data
  -d DECRYPT, --decrypt DECRYPT
                        Decrypt base64 encode cipher text
  -v, --verb            Show decrypt block info

```
The exploit recieve the URL of the resource which require oracle OAM authentication. It does the below steps:
1. find the correct length that results in adding new padding block
2. brute-force the correct prefix that will be used in future encryption and decryption (magic block)

The pentester can specify any encrypted value (encquery, encreplay, cookie) he wish to decrypt using the ```-d``` flag.

The pentester can specify any plain text value he wish to encrypt using the ```-e``` flag.

### Constructing a fake cookie
by reversing oracle OAM sdk we can see that the cookie consists of the below structure
```
Salt= ACL= AuthId= Ip= TCT= SessionId= userId= validate=BASE64Encode(MD5(Salt+AuthId+Ip+ACL+TCT+SessionId))

```
So to build a cookie, get a valid plain text one using ```-d``` flag, modify it then encrypt it again using ```-e```.

### Example of decrypting a cookie
![Alt text](example/1.jpg?raw=true "CMD")
![Alt text](example/2.JPG?raw=true "output")
