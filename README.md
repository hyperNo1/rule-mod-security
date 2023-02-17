# rule-mod-security for office
This rule set checks several things:

Checks the file extension of uploaded files to make sure they are a Word document or Excel spreadsheet (the rule matches .doc, .docx, .xls, and .xlsx).
Checks that the file names do not contain any potentially dangerous extensions such as .vbs, .hta, or .js.
Checks that the multipart form data is well-formed.
Checks that the content type of the uploaded file is multipart/form-data.
Checks the uploaded file and the request body for .odb or .rtf file extensions.
Checks for specific keywords associated with Office macros, indicating that the uploaded file may contain a macro.

#rule detect and prevent exploit attempts that try to bypass the Web Application Firewall 
rules aim to block requests that contain encoded slashes, encoded NULL bytes, UTF-8 or URL-encoded entities, or invalid characters in parameter names or values. 
Such requests can be used to bypass WAF protections and exploit vulnerabilities in web applications. 
The rules are based on OWASP guidelines for preventing evasion techniques used by attackers to bypass WAFs.
#rule of modsecurity for exploit blind-SQLinjection , Unrestricted file upload include zipslip and based file upload race condition
detect blind SQL injection attempts, ZipSlip attacks, and exploit tools such as w3af, ZAP, BurpSuite, and sqlmap. 
The last rule is a whitelist that allows traffic from specified IP addresses.
