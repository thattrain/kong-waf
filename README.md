# Kong WAF

This project attempt to integrate [Coraza](https://coraza.io/) which is a Web application firewall (WAF) or firewall level 7 engine and OWASP CRS into Kong Gateway.

Key feature: 

* ⇲ **Drop-in** - Coraza is a drop-in alternative to replace the soon to be abandoned Trustwave ModSecurity Engine and supports industry standard SecLang rule sets.
* 🔥 **Security** -  Coraza runs the [OWASP Core Rule Set (CRS)](https://coreruleset.org) **v4** to protect your web applications from a wide range of attacks, including the OWASP Top Ten, with a minimum of false alerts. CRS protects from many common attack categories including: SQL Injection (SQLi), Cross Site Scripting (XSS), PHP & Java Code Injection, HTTPoxy, Shellshock, Scripting/Scanner/Bot Detection & Metadata & Error Leakages. Note that older versions of the CRS are not compatible.
* **Dynamic configuration** - Kong-waf is dynamically through Kong admin API.
* **Compatibility** - Compatible with all Kong deployment topologies: hybrid, traditional and DB less.

Core rule set version: 4.5.0

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
- LogLevel and LogPath if left empty is already automatically assigned in coraza.conf
- <strong> ParanoidLevel must be hard configured at crs-setup.conf </strong>

```go

type Config struct {

	// WAF mode
	DetectionMode bool `json:"detection_mode" ` // log matched request
	EnforceMode   bool `json:"enforce_mode"`    // block matched request
	EnableAll     bool `json:"enable_all"`      //	enable all protection strategy

	// logging configuration if DetectionMode is true
	LogPath  string `json:"log_path"`  // debug log path (consider to create a separate log file for each scope that this plugin apply)
	LogLevel int    `json:"log_level"` // default to Info (3), value 1-9: Error(1), Warn(2), Info(3), Debug(4-8), Trace(9)

	// protection strategy when EnableAll is false
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




## Benchmark 

//todo
