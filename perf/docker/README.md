# Quinn performance network simulator

This docker file and set of scripts allow running a performance test using
`quinn-perf` binary.

## Building

### Standard binary

To build the `quinn-perf` binary and docker image use the following command:

```sh
./build.sh
```

### Instrumented binary

To build an instrumented `quinn-perf` binary that allows supervision using
[`tokio-console`](https://github.com/tokio-rs/console), use the following
command:

```sh
./build.sh -t
```

## Launching

### Server

To launch `quinn-perf server` use the following command:
```sh
./run-server.sh
```

### Client

To launch `quinn-perf client` use the following command:
```sh
./run-client.sh
```
It connects to `quinn-perf server` running in docker.

### Arguments

| name     | help                                        | description                         |
| :-:      | :-:                                         | :-:                                 |
| `-h`     | display help                                |                                     |
| `-c`     | enable packet capture                       | capture will be stored in `./work/` |
| `-g`     | enabled GSO                                 | default: disabled                   |
| `-l num` | specify simulated latency in ms             | default: 0ms                        |
| `-L num` | specify simulated packet loss in percentage | default: 0%                         |
| `-o`     | open packet capture                         | requires `-c`                       |
| `-t`     | attach to tokio console                     | requires an instrumented binary     |

#### Change default `quinn-perf` arguments

`--` can be used to add additional arguments for `quinn-perf` binary.

Example:
```sh
./run-client.sh -g -l 5 -- --help
```
shows `quinn-perf` available arguments.

Example:
```sh
./run-client.sh -g -l 5 -- --download-size 5M --upload-size 5M --duration 10
```
runs a bidirectional download and upload benchmark of 5 MB per stream for 10
seconds.

## Simulate network latency or packet loss

Argument `-l` can be used to simulate network latency.

If you want to simulate a 10ms latency, launch server with `-l 5` argument and
launch client with `-l 5` argument.

Argument `-L` can be used to simulate network packet loss.

If you want to simulate a `0.1%` loss link, launch server with `-L 0.1` argument and
launch client with standard arguments.

Latency is simulated at network interface level using linux kernel QoS ([`tc
netem`](https://man7.org/linux/man-pages/man8/tc-netem.8.html)).

Scripts display some statistics at the end of the run.

## Capture packets

Argument `-c` can be used to enable packet capture. Dumps are stored in
`./work/`. By default `quinn-perf` is configured to dump the cryptographic keys
in the same folder.

Argument `-o` can be used to open the packet capture at the end of the
benchmark using [`wireshark`](https://www.wireshark.org/) (which must be
installed).

## Analyze using `tokio-console`

To instrument and monitor `quinn-perf` using `tokio-console` (which must be installed), compile using:
```sh
./build.sh -t
```

Then launch server and client using wanted options.

Then run:
```sh
./run-server.sh -t
```
to launch `tokio-console` and attach it to server binary.

Then run:
```sh
./run-client.sh -t
```
to launch `tokio-console` and attach it to client binary.

