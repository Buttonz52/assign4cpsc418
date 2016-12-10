CPSC 418 - Assignment 4 Coding README - Brendan Petras 10137098

FILE LIST
---------
Client.java				-unchanged
CryptoUtilities.java			-unchanged
Server.java				-unchanged
ServerThread.java			-unchanged
RSATool.java				-allows for RSA,RSA-OAEP, and toggling of CRT
JPEG.jpg 				-test file
README.txt 				-README file
stuff.zip 				-test file

COMPILE
-------
Javac *.java

RUN
---
In two terminal windows T1 and T2, 
T1) Java Server <port#> <debug>
T2) Java Client <IP> <port#> <debug>

NOTES
-----
Solved in full
No known bugs
May take longer than last assignment since computing two sophie germain primes of 512 bytes

Solved with RSA-OAEP with optimization using CRT.


Description of Implementation
-----------------------------
(p = 2*l + 1) - with l as some random  512 byte prime
(q = 2*r + 1) - with r as some random  512 byte prime
(e = 3 if gcd(e,phi(n)) = 1, else try again with e +=2)
(ed = 1 mod( phi(n)), so d is the modular inverse of e mod phi(n). 