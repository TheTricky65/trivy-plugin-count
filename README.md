# trivy-plugin-count
Using this already made version of the plugin trivy-plugin-count.

## Installation
```shell
trivy plugin install github.com/TheTricky65/trivy-plugin-count
```
## Usage

1) build the go project 
```shell
go build 
```
2) execute the binary
```shell
./trivy-plugin-count --report <Trivy json report path> --severity <severity>
```




Below are the steps for the current official plugin count to exist.

## Usage

```shell
trivy <target> --format json --output plugin=count [--output-plugin-arg plugin_flags] <target_name>
```

OR

```shell
trivy <target> -f json <target_name> | trivy count [plugin_flags]
```

## Examples

```shell
trivy image -f json -o plugin=count --output-plugin-arg "--published-after=2023-11-01" debian:12
```

is equivalent to:

```shell
trivy image -f json debian:12 | trivy count --published-after=2023-11-01
```
