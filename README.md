# Description

Mrinfo is a multicast routing information utility for GNU/Linux, similar to the
implementation provided on Cisco IOS.<br/>
Feel free to contact me for bug fixes or feature requests.
#Example output
&nbsp;&nbsp;./mrinfo 192.168.2.4<br/>
&nbsp;&nbsp;192.168.2.4 [Version 12.4] [Capabilities PM]:<br/>
&nbsp;&nbsp;&nbsp;&nbsp;192.168.2.4 -> 192.168.2.2 [1/0/Querier]<br/>
&nbsp;&nbsp;&nbsp;&nbsp;192.168.2.4 -> 192.168.2.3 [1/0/Querier]<br/>
&nbsp;&nbsp;&nbsp;&nbsp;192.168.13.3 -> 192.168.13.1 [1/0/Querier]<br/>
#Usage
* Simple probe.
 * ./mrinfo <target>
* With 5 seconds timeout
 * ./mrinfo -t 5 <target>
* Show help
 * ./mrinfo -h

#Build:
$ make<br/>
&nbsp;Dependencies: libpcap (Responses capturing.)
