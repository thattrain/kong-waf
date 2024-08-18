# Kong WAF

This project attempt to integrate [Coraza](https://coraza.io/) which is a Web application firewall (WAF) or firewall level 7 engine and OWASP CRS into Kong Gateway.

Key feature: 

* ⇲ **Drop-in** - Coraza is a drop-in alternative to replace the soon to be abandoned Trustwave ModSecurity Engine and supports industry standard SecLang rule sets.
* 🔥 **Security** -  Coraza runs the [OWASP Core Rule Set (CRS)](https://coreruleset.org) **v4** to protect your web applications from a wide range of attacks, including the OWASP Top Ten, with a minimum of false alerts. CRS protects from many common attack categories including: SQL Injection (SQLi), Cross Site Scripting (XSS), PHP & Java Code Injection, HTTPoxy, Shellshock, Scripting/Scanner/Bot Detection & Metadata & Error Leakages. Note that older versions of the CRS are not compatible.
* **Dynamic configuration** - Kong-waf is dynamically through Kong admin API.
* **Compatibility** - Compatible with all Kong deployment topologies: hybrid, traditional and DB less.
* **Core rule set version: 4.5.0**
* **Kong gateway version: 3.7.1**


## Build source
Install all dependencies

``go mod tind && go mod download``

## Build 

``go build``

## Build a custom Kong image and include Kong WAF as plugin:

1. Build Kong image with custom plugin included

``docker build -t kong:[desired tag] .``

2. Include kong-waf plugin at Kong configuration when start Kong instance

``
-e "KONG_PLUGINS=bundled,kong-waf" 
-e "KONG_PLUGINSERVER_NAMES=kong-waf" 
-e "KONG_PLUGINSERVER_KONG_WAF_QUERY_CMD=/usr/local/bin/kong-waf -dump" 
``

## WAF instance configuration

- Config The value in each field of this struct is not validate such as plugin schema written in Lua
  any invalid value is ignored, empty value is default value of each data type, eg: bool -> false. </br>
- LogLevel and SecDebugLogPath if left empty is already automatically assigned in coraza.conf
- <strong> ParanoidLevel must be hard configured at crs-setup.conf (default value is 1) </strong>

```go

type Config struct {

// WAF mode
DetectionMode bool `json:"detection_mode" ` // log matched request
EnforceMode   bool `json:"enforce_mode"`    // block matched request

// logging configuration
SecDebugLogPath string `json:"debug_log_path"` // debug log path
LogLevel        int    `json:"log_level"`      // default to Info (3), value 1-9: Error(1), Warn(2), Info(3), Debug(4-8), Trace(9)
SecAuditLogPath string `json:"audit_log_path"` // audit log path, SecAuditLogParts is hard coded to 'ABIJDEFHKZ' which record everything about the transaction

// protection strategy when EnableAll is false
EnableAll              bool `json:"enable_all"`               // enable all protection strategy
ScannerDetection       bool `json:"scanner_detection"`        // enable scanner detection
MultipartProtect       bool `json:"multipart_protect"`        // enable multipart protection
RceProtect             bool `json:"rce_protect"`              // enable remote code execution protect
PhpProtect             bool `json:"php_protect"`              // enable PHP protection
GenericProtection      bool `json:"generic_protection"`       // enable generic web protection
XssProtect             bool `json:"xss_protect"`              // enable XSS protection
SqlInjectionProtect    bool `json:"sql_injection_protect"`    // enable SQl injection protection
SessionFixationProtect bool `json:"session_fixation_protect"` // enable session fixation protection
JavaProtect            bool `json:"java_protect"`             // enable Java protection
WebShellProtect        bool `json:"webshell_protect"`         // enable web shell protection
}


```


## Test with Go-FTW - Framework for Testing WAFs in Go!

Prerequisite:
- Active Kong gateway and Kong proxy.
- A backend service protected by Kong-WAF plugin.
- [Go-FTW](https://github.com/coreruleset/go-ftw) must be installed, checkout their documentation for installation and detail testing configuration.
- Using test rule reference from [Coreruleset](https://github.com/coreruleset/coreruleset), test rule should be compatible with CRS version using in Kong-WAF setup.

Test command: 

```bash
$HOME/go/bin/go-ftw run --config .ftw.kong-waf.yaml -d ../coreruleset/tests/regression/tests/
```

Result:

```bash
🛠️ Starting tests!
🚀 Running go-ftw!
👉 executing tests in file
	running 911100-1: ✔ passed in 16.763042ms (RTT 63.269542ms)
	running 911100-2: ✔ passed in 17.965375ms (RTT 67.659042ms)
	running 911100-3: ✔ passed in 6.677042ms (RTT 56.261583ms)
	running 911100-4: ✔ passed in 3.709167ms (RTT 52.710875ms)
	running 911100-5: ✔ passed in 3.581125ms (RTT 53.355167ms)
	running 911100-6: ✔ passed in 3.377417ms (RTT 53.159333ms)
	running 911100-7: ✔ passed in 3.73925ms (RTT 53.485833ms)
	running 911100-8: ✔ passed in 2.243917ms (RTT 51.917583ms)
...
👉 executing tests in file
	running 980170-1: ✔ passed in 1.942667ms (RTT 51.762083ms)
	running 980170-2: ✔ passed in 1.686083ms (RTT 51.464917ms)
	running 980170-3: ✔ passed in 2.215792ms (RTT 52.041292ms)
➕ run 3845 total tests in 10.577154489s
⏭ skipped 0 tests
👎 8 test(s) failed to run: ["920100-4" "920100-8" "920181-1" "920270-4" "920272-5" "920274-1" "920610-2" "920620-1"]
Error: failed 8 tests
```







## Benchmark 

//todo
