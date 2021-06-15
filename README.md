# Deauthentication-Attack

## Pre-preparations:

1. Python 3.x installed + “scapy” installed.
2. Network card that have the ability to work on monitor mode.
3. Know if the network you search for working in 2.4Ghz or 5Ghz(in our case 5Ghz couldn't be found).

## Documentation of code usage:

 ![‏‏לכידה](https://user-images.githubusercontent.com/44755169/122076642-b8779300-ce03-11eb-8be7-1583313fc08d.JPG)


1. You need to enter the name of the network card you want to use.

2. Enter the channel you want the program to search or press enter and it will search in all channels).

3. The “scapy” sniff function will find all the Access point MAC addresses and victims that connect to those networks, and print them all.

4. After the search all the AP will shown and you will need to choose the relevant AP MAC.

5. After choosing the AP, there will be printed a list of all victims that connected to this network, choose one of them and enter the place number of his MAC.

6. After all that, you will see that the malicious packet sent to the client and disconnect him from the network.
