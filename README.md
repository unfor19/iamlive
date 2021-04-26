# iamlive

> Generate an IAM policy from AWS calls using client-side monitoring (CSM) or embedded proxy

![](https://raw.githubusercontent.com/iann0036/iamlive/assets/iamlive.gif)

## Installation

### Pre-built binaries

Pre-built binaries for Windows, macOS and Linux are available for download in the project [releases](https://github.com/iann0036/iamlive/releases).

Once downloaded, place the extracted binary in your $PATH (or execute in-place). For macOS users, you may need to allow the application to run via System Preferences.

### Build with Go

To build and install this application, clone this repository and execute the following from it's base:

```
go install
```

You must have Go 1.16 or later installed for the build to work.

### Homebrew

You may also install this application using a Homebrew tap with the following command:

```
brew install iann0036/iamlive/iamlive
```

## Usage

To start the listener, simply run `iamlive` in a separate window to your CLI / SDK application. You can use Ctrl+C to exit when you are done.

### CLI Arguments

You can optionally also include the following arguments to the `iamlive` command:

**--set-ini:** when set, the `.aws/config` file will be updated to use the CSM monitoring or CA bundle and removed when exiting (_default: false_)

**--profile:** use the specified profile when combined with `--set-ini` (_default: default_)

**--fails-only:** when set, only failed AWS calls will be added to the policy, csm mode only (_default: false_)

**--output-file:** specify a file that will be written to on SIGHUP or exit (_default: unset_)

**--refresh-rate:** instead of flushing to console every API call, do it this number of seconds (_default: 0_)

**--sort-alphabetical:** sort actions alphabetically (_default: false_)

**--host:** host to listen on for CSM (_default: 127.0.0.1_)

**--background:** when set, the process will return the current PID and run in the background without output (_default: false_)

**--force-wildcard-resource:** when set, the Resource will always be a wildcard (_default: false_)

**--mode:** _[experimental]_ the listening mode (`csm`,`proxy`) (_default: csm_)

**--bind-addr:** _[experimental]_ the bind address for proxy mode (_default: 127.0.0.1:10080_)

**--ca-bundle:** _[experimental]_ the CA certificate bundle (PEM) to use for proxy mode (_default: ~/.iamlive/ca.pem_)

**--ca-key:** _[experimental]_ the CA certificate key to use for proxy mode (_default: ~/.iamlive/ca.key_)

**--account-id:** _[experimental]_ the AWS account ID to use in policy outputs within proxy mode (_default: 123456789012 unless detected_)

_Basic Example (CSM Mode)_

```
iamlive --set-ini
```

_Basic Example (Proxy Mode)_

```
iamlive --set-ini --mode proxy
```

_Comprehensive Example (CSM Mode)_

```
iamlive --set-ini --profile myprofile --fails-only --output-file policy.json --refresh-rate 1 --sort-alphabetical --host 127.0.0.1 --background
```

_Comprehensive Example (Proxy Mode)_

```
iamlive --set-ini --mode proxy --profile myprofile --output-file policy.json --refresh-rate 1 --sort-alphabetical --bind-addr 127.0.0.1:10080 --ca-bundle ~/.iamlive/ca.pem --ca-key ~/.iamlive/ca.key --account-id 123456789012 --background --force-wildcard-resource
```

The arguments may also be specified in an INI file located at `~/.iamlive/config`.

### CSM Mode

Client-side monitoring mode is the default behaviour and will use [metrics](https://docs.aws.amazon.com/sdk-for-javascript/v2/developer-guide/metrics.html) delivered locally via UDP to capture policy statements with the `Action` key only (`Resource` is only available in proxy mode).

#### CLI

To enable CSM in the AWS CLI, you should either use the `--set-ini` option or add the following to the relevant profile in `.aws/config`:

```
csm_enabled = true
```

Alternatively, you can run the following in the window executing your CLI commands:

```
export AWS_CSM_ENABLED=true
```

#### SDKs

To enable CSM in the various AWS SDKs, you can run the following in the window executing your application prior to it starting:

```
export AWS_CSM_ENABLED=true
export AWS_CSM_PORT=31000
export AWS_CSM_HOST=127.0.0.1
```

### Proxy Mode

Proxy mode will serve a local HTTP(S) server (by default at `http://127.0.0.1:10080`) that will inspect requests sent to the AWS endpoints before forwarding on to generate IAM policy statements with both `Action` and `Resource` keys. The CA key/certificate pair will be automatically generated and stored within `~/.iamlive/` by default.

#### CLI

To set the appropriate CA bundle in the AWS CLI, you should either use the `--set-ini` option or add the following to the relevant profile in `.aws/config`:

```
ca_bundle = ~/.iamlive/ca.pem
```

Alternatively, you can run the following in the window executing your CLI commands:

```
export AWS_CA_BUNDLE=~/.iamlive/ca.pem
```

You must also set the proxy settings for your session by running the following in the window executing your CLI commands:

```
export HTTP_PROXY=http://127.0.0.1:10080
export HTTPS_PROXY=http://127.0.0.1:10080
```

#### Docker

Build Docker image from source

```bash
docker build -t iamlive .
```

Run Docker container in Proxy Mode

```bash
docker run \
  -p 80:10080 \
  -p 443:10080 \
  --name iamlive \
  -it iamlive \
  --mode proxy \
  --bind-addr 0.0.0.0:10080 \
  --force-wildcard-resource \
  --output-file "/app/iamlive.log"
# Runs in the background ...
```

Instruct tools that use AWS SDK, such as [aws-cli](https://aws.amazon.com/cli/) and [terraform](https://www.terraform.io/docs/cli/commands/index.html), to use the local proxy server - `iamlive` Docker container.

```bash
export HTTP_PROXY=http://127.0.0.1:80 \
       HTTPS_PROXY=http://127.0.0.1:443 \
       AWS_CA_BUNDLE="${HOME}/.iamlive/ca.pem"
```

Copy the Certificate Authority Certificate (`ca.pem`) that was generated by the `iamlive` Docker container, to your local machine (Host).

```bash
docker cp iamlive:/home/appuser/.iamlive/ ~/
```

Test the local proxy server by invoking some `aws` command

```bash
aws s3 ls
# Output
# An error occurred (AccessDenied) when calling the ListBuckets operation: Access Denied
```

Check the logs of the `iamlive` container, should look like this

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets"
            ],
            "Resource": "*"
        }
    ]
}
```

It's important to mention that `terraform init` cannot be proxied via `iamlive` since it attempts to access [registry.terraform.io](registry.terraform.io), and it's not covered by `iamlive`. So first, unset the proxy settings, and then execute `terraform init`. Following that, execute `terraform apply` and check the logs of the `iamlive` container.

```bash
unset HTTP_PROXY HTTPS_PROXY AWS_CA_BUNDLE
terraform init
# Terraform has been successfully initialized!

# Instruct CLIs to use iamlive local proxy server
export HTTP_PROXY=http://127.0.0.1:80 \
       HTTPS_PROXY=http://127.0.0.1:443 \
       AWS_CA_BUNDLE="${HOME}/.iamlive/ca.pem"

# In terraform-iamlive dir
terraform apply
```

To stop the `iamlive` Docker container hit `CTRL+C`. The `ca.pem` is preserved because the Docker container has stopped but wasn't removed. To re-run `iamlive` Docker container, execute the following command

```bash
# Hit CTRL+C To stop the container

docker start -i iamlive
# Keep it running in the background
```


#### SDKs

To enable CSM in the various AWS SDKs, you can run the following in the window executing your application prior to it starting:

```
export HTTP_PROXY=http://127.0.0.1:10080
export HTTPS_PROXY=http://127.0.0.1:10080
export AWS_CA_BUNDLE=~/.iamlive/ca.pem
```

Check the [official docs](https://docs.aws.amazon.com/credref/latest/refdocs/setting-global-ca_bundle.html) for further details on setting the CA bundle.

## FAQs

_I get a message "package embed is not in GOROOT" when attempting to build myself_

This project requires Go 1.16 or above to be built correctly (due to embedding feature).

## Acknowledgements

This project makes use of [Parliament](https://github.com/duo-labs/parliament) and was assisted by Scott Piper's [CSM explainer](https://summitroute.com/blog/2020/05/25/client_side_monitoring/). Thanks also to Noam Dahan's [research](https://ermetic.com/whats-new/blog/auditing-passrole-a-problematic-privilege-escalation-permission/) into missing `iam:PassRole` dependant actions.
