# Wrangler

An interface for running command line applications. Wrangler uses Golang's concurrency model (goroutines and channels) to execute commands and parse stdout, stderr and tool reports. Reports are typically required to be standardised format, like XML.
Wrangler attempts to use this model to optimise the execution of long-running CLI tasks such as Nmap, testssl.sh etc. Whilst these tasks finish quickly in small batches, if many thousands of targets are set, scans can take a LONG time!

Wrangler attempts to do this by using a multi-stage process and pipeline. A single target set can be run over multiple concurrent pipelines divided into 'batches' of IP addresses or FQDNs. Note that if a CIDR block is specified, Wrangler will break out each possible individual IP address.

Whilst it may be possible to create a separate Nmap process for each host, this causes untenable system resource overhead. This is why batches are used. This still creates a chonky boi of an overhead, but it will be more manageable once the total number of concurrent batches is rate limited (TBC).

1. Establish which hosts are up using a thorough `nmap -sn` variation.
2. Hosts which are up are fed into a 'host discovery'. This can use a lightweight TCP or SYN packet to establish which ports are open. 
3. This data is then fed into a series of full scans which are templated in and loaded from a custom YAML file. 
4. Scans will target all ports have been confirmed as OPEN by Nmap. This greatly reduces redundant scanning of filtered host ports.
5. All data is dumped out to a user specified reports directory using Nmap's `-oA` flag.

Currently only service discovery on TCP is supported. This will have to be extended to support UDP and to categorise ports by UDP, TCP, both or other.

### Assign CAP

```sh
> sudo apt-get install libcap2-bin 
> sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
> getcap $(which nmap)
/usr/bin/nmap cap_net_bind_service,cap_net_admin,cap_net_raw=eip
```

## TODO:

1. Implement SCTP support. 
2. Rate limiting on number of concurrent batches.
3. Implement another layer of host discovery checking for at least one open port
4. Review host discovery nmap approach
