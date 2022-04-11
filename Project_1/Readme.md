# IPK Project 1 -server
Hinfosvc is a server in C, which communicates using HTTP protocol. The server responds to various requests and retrieves specific information about the system. Communication with the server is possible through web brouser or using tools such as wget and curl. 
Server is able to respond on these 3 requests, sent by GET command:
+ domain name: GET http://servername:12345/hostname
+ information about cpu: GET http://servername:12345/cpu-name
+ current load: GET http://servername:12345/load

### Running the server

$ Use make to build the program. 
$ Run the program with an argument specifying local port where server will listen to requests:

  ```
  ./hinfosvc <port_number>
  ```

  For example.

  ```
  ./hinfosvc 12345
  ```

## Usage

Usage examples with curl. (After running the server ./hinfosvc <port_number>)

```
+ curl http://localhost:12345/hostname

	merlin.fit.vutbr.cz

+ curl http://localhost:12345/cpu-name

	Intel(R) Xeon(R) CPU E5-2640 0 @ 2.50GHz

+ curl http://localhost:12345/load

	65%

## Contributors

*Lucia Makaiová*  [xmakai00]
