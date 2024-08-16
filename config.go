package main

// Config The value in each field of this struct is not validate such as plugin schema written in Lua
// any invalid value is ignored, empty value is default value of each data type, eg: bool -> false.
//
// LogLevel and SecDebugLogPath if left empty is already automatically assigned in coraza.conf
type Config struct {

	// WAF mode
	DetectionMode bool `json:"detection_mode" ` // log matched request
	EnforceMode   bool `json:"enforce_mode"`    // block matched request
	EnableAll     bool `json:"enable_all"`      //	enable all protection strategy

	// logging configuration if DetectionMode is true
	SecDebugLogPath string `json:"debug_log_path"` // debug log path
	LogLevel        int    `json:"log_level"`      // default to Info (3), value 1-9: Error(1), Warn(2), Info(3), Debug(4-8), Trace(9)
	SecAuditLogPath string `json:"audit_log_path"` // audit log path

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
