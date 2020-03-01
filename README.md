# Osquery-memory-forensics

<p align="center">
  <img width="460" height="300" src=".img/memory_gopher.png">
</p>

For several years I have always wanted to write an Osquery extension to perform memory dumps and analysis. I never got the time to do a deep into my idea but since I have been creating some Osquery-go extensions lately I decided to take a whack at my idea. This blog post will provide a high overview of the architecture of this Osquery extension, how to generate memory dumps with Osquery, and how to remotely analyze these memory dumps with Osquery. Follow me another threat detection engineering experience with osquery-go.

* [Dumping and analyzing memory with Osquery and Kolide](https://holdmybeersecurity.com/2020/03/01/dumping-and-anal…query-and-kolide/)

## Setup dev env
1. `go mod init github.com/CptOfEvilMinions/osquery-memory-forensics`
1. `go get`

## Compile osquery_dump table
### Download bins and make
1. Download [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)
1. Download [DumpIt](https://blog.comae.io/your-favorite-memory-toolkit-is-back-f97072d33d5c)
1. Copy binaries to `bins/dump` as `procdump.exe` and `dumpit.exe`

### Make go-bindata
1. `go get -u github.com/go-bindata/go-bindata/...`
1. `go install github.com/go-bindata/go-bindata/...`
1. `~/go/bin/go-bindata -o assets/dump/bindata.go -pkg dump bins/dump/...`
1. `ls -lh assets/dump/bindata.go`

### Compile
1. `GOOS=windows go build -o osquery_memory_forensic_dump.exe cmd/dump/osquery-memory-forensics-dump.go`

## Compile osquery_analyze table
### Download bins
1. Download [Volatility v3](https://github.com/volatilityfoundation/volatility3/releases/download/v1.0.0-beta.1/volatility3-windows-binaries-1.0.0-beta.1.zip)
1. Copy binary do `bins/analyze` as `volatility.exe`

### Make go-bindata
1. Copy binary do `bins/analyze` as `volatility.exe`
1. `~/go/bin/go-bindata -o assets/analyze/bindata.go -pkg analyze bins/analyze/...`
1. `ls -lh assets/analyze/bindata.go`

### Compile
1. `GOOS=windows go build -o osquery_memory_forensic_analyze.exe cmd/osquery-memory-forensics-analysis/osquery-memory-forensics-analyze.go`

## Using a different memory dumper (osquery_memory_forensics_dump)
1. Modify `pkg/dumpers/dumpers.go`

## Using a different memory analysis framework (osquery_memory_forensic_analyze)
1. Copy new binary to `bins/analyze`
1. Follow instructions above to make new go-bindata
1. Modify `pkg/volatility/volatility.go` to support your tool with the proper commands

## References
* [Combine absolute path and relative path to get a new absolute path](https://stackoverflow.com/questions/13078314/combine-absolute-path-and-relative-path-to-get-a-new-absolute-path)
* [Go by Example: Epoch](https://gobyexample.com/epoch)
* [PsExec gets stuck on licence prompt when running non-interactively](https://stackoverflow.com/questions/5151034/psexec-gets-stuck-on-licence-prompt-when-running-non-interactively)
* [Package strconv](https://golang.org/pkg/strconv/)
* [ProcDump v9.0](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)
* [Go and file perms on Windows](https://medium.com/@MichalPristas/go-and-file-perms-on-windows-3c944d55dd44)
* [Hash checksums: MD5, SHA-1, SHA-256](https://yourbasic.org/golang/hash-md5-sha256-string-file/)
* [Github - getlantern/byteexec](https://github.com/getlantern/byteexec)
* [package byteexec](https://pkg.go.dev/github.com/getlantern/byteexec?tab=doc#Exec)
* [Embedding data in Go executables](https://scene-si.org/2017/08/22/embedding-data-in-go-executables/)
* [Github - go-bindata/go-bindata](https://github.com/go-bindata/go-bindata)
* [StackOverFlow - How can I get the user's AppData folder path with golang?](https://stackoverflow.com/questions/56181604/how-can-i-get-the-users-appdata-folder-path-with-golang)
* [Golang hash sum and checksum to string tutorial and examples](https://mrwaggel.be/post/golang-hash-sum-and-checksum-to-string-tutorial-and-examples/)
* [Package sha256](https://golang.org/pkg/crypto/sha256/)
* [Go: Read a whole file into a string (byte slice)](https://programming.guide/go/read-file-to-string.html)
* [Self-hosting Sentry With Docker and Docker-compose](https://mikedombrowski.com/2018/03/self-hosting-sentry-with-docker-and-docker-compose/)
* [Kolide - Configuring The Fleet Binary](https://github.com/kolide/fleet/blob/master/docs/infrastructure/configuring-the-fleet-binary.md)
* [DockerHub - MySQL](https://hub.docker.com/_/mysql?tab=description)
* [DockerHub - Kolide](https://hub.docker.com/r/kolide/fleet)
* [Go Date and Time Formatting](https://flaviocopes.com/go-date-time-format/)
* [NGINX as a WebSocket Proxy](https://www.nginx.com/blog/websocket-nginx/)
* [DockerHub - NGINX](https://hub.docker.com/_/nginx?tab=tags)
* [Powershell Set-Content](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-content?view=powershell-7)
* [WinPmem](https://github.com/Velocidex/c-aff4/releases/download/v3.3.rc3/winpmem_v3.3.rc3.exe)