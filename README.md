# Host-Based-Firewall

Steps to run the code:
----------------------

1) clone repository.
2) cd src/
3) Either change the already existing "input.csv" file or create new rule csv file.
4) compile the program using command "javac Firewall.java"
5) run the program using command "java Firewall input.csv". Or provide new csv file's absolute path.
6) Enter arguments comma separated in the following order: `direction , protocol , port , ip_address`
  for example: `inbound,tcp,80,192.168.1.2`
7) Type "end" to stop the program.



NOTE:
-------
* Loggers are used to log invalid input or exceptions.
* Time Complexity is O(n).
* Space Complexity is O(n). 
* Few JUnit test cases are written (test/ directory).
