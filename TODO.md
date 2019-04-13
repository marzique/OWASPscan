## bug fixes/features
- do not consider redirects with 200 ok if url changed

## Refactor
- separate 'configer' actions to their modules

### Main Modules

## INJECTOR:
- SQL
	- sqlmap or similar (via url)
	- maybe something like form break (integrate with admin pages !)
- XML, deserialize
	- Somehow check if we have something to do with XML/serializing
	- if we do - check vulnurabilities
- XSS
	- find out best python way to check it

## AUTHENTIFICATOR:
- try to bruteforce pages - can we or not
- check vocabulary attack
- check for CAPTCHA
- 

## CVE
- check folder via API

## CONFIGER
- check for more sensitive info possible

### Output
- Fancy PDF (or similar) report with GREEN vs RED parts, connect it with OWASP TOP 10 list
- Maybe e-mail it.


