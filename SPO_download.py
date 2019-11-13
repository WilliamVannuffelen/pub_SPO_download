import sys
import requests
import uuid
from datetime import datetime,timezone,timedelta

###							###
###  FUNCTION DEFINITIONS	###
###							###

# Step 1:
# Get target URL to POST for SAML assertion retrieved by POSTing UserPrincipalName to home realm discovery page
# username must be entered in UPN format: username@domain
def retrieve_custom_stsauth_url(username):
	url = "https://login.microsoftonline.com/GetUserRealm.srf"

	response_object = requests.post(url,data="login={0}&xml=1".format(username))
	response_text = response_object.text

	start_keyword = "<STSAuthURL>" 
	stop_keyword =  "</STSAuthURL>"
	start_index = response_text.find(start_keyword)
	stop_index = response_text.find(stop_keyword)

	custom_stsauth_url = response_text[start_index+len(start_keyword):stop_index]

	return custom_stsauth_url

# Step 2:
# Get SAML assertion from custom STS endpoint by POSTing authentication SOAP XML to custom STS endpoint (= ADFS)
def retrieve_saml_assertion(custom_stsauth_url,username,password):
	message_id = uuid.uuid4()
	username = username
	password = password
	created = datetime.utcnow().replace(tzinfo=timezone.utc).isoformat()
	expires = (datetime.utcnow() + timedelta(minutes=10)).replace(tzinfo=timezone.utc).isoformat()
	token_issuer_uri = "urn:federation:MicrosoftOnline"

	post_body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:saml=\"urn:oasis:names:tc:SAML:1.0:assertion\" xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" xmlns:wsa=\"http://www.w3.org/2005/08/addressing\" xmlns:wssc=\"http://schemas.xmlsoap.org/ws/2005/02/sc\" xmlns:wst=\"http://schemas.xmlsoap.org/ws/2005/02/trust\"><s:Header><wsa:Action s:mustUnderstand=\"1\">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</wsa:Action><wsa:To s:mustUnderstand=\"1\">{0}</wsa:To><wsa:MessageID>{1}</wsa:MessageID><ps:AuthInfo xmlns:ps=\"http://schemas.microsoft.com/Passport/SoapServices/PPCRL\" Id=\"PPAuthInfo\"><ps:HostingApp>Managed IDCRL</ps:HostingApp><ps:BinaryVersion>6</ps:BinaryVersion><ps:UIVersion>1</ps:UIVersion><ps:Cookies></ps:Cookies><ps:RequestParams>AQAAAAIAAABsYwQAAAAxMDMz</ps:RequestParams></ps:AuthInfo><wsse:Security><wsse:UsernameToken wsu:Id=\"user\"><wsse:Username>{2}</wsse:Username><wsse:Password>{3}</wsse:Password></wsse:UsernameToken><wsu:Timestamp Id=\"Timestamp\"><wsu:Created>{4}</wsu:Created><wsu:Expires>{5}</wsu:Expires></wsu:Timestamp></wsse:Security></s:Header><s:Body><wst:RequestSecurityToken Id=\"RST0\"><wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType><wsp:AppliesTo><wsa:EndpointReference><wsa:Address>{6}</wsa:Address></wsa:EndpointReference></wsp:AppliesTo><wst:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</wst:KeyType></wst:RequestSecurityToken></s:Body></s:Envelope>".format(custom_stsauth_url,message_id,username,password,created,expires,token_issuer_uri)
	headers = {'Content-Type':'application/soap+xml'}

	response_object = requests.post(custom_stsauth_url,headers=headers,data=post_body)
	response_text = response_object.text
	start_keyword = "<saml:Assertion" 
	stop_keyword = "</saml:Assertion>"
	start_index = response_text.find(start_keyword)
	stop_index = response_text.find(stop_keyword)
	
	saml_assertion = response_text[start_index:stop_index+len(stop_keyword)]

	return saml_assertion

# Step 3:
# Get Binary security token from default MSO STS endpoint by POSTing authentication SOAP XML with SAML assertion
def retrieve_binary_token(saml_assertion,mso_domain):
	default_stsauth_url = "https://login.microsoftonline.com/rst2.srf"
	
	post_body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><S:Envelope xmlns:S=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" xmlns:wsa=\"http://www.w3.org/2005/08/addressing\" xmlns:wst=\"http://schemas.xmlsoap.org/ws/2005/02/trust\"><S:Header><wsa:Action S:mustUnderstand=\"1\">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</wsa:Action><wsa:To S:mustUnderstand=\"1\">https://login.microsoftonline.com/rst2.srf</wsa:To><ps:AuthInfo xmlns:ps=\"http://schemas.microsoft.com/LiveID/SoapServices/v1\" Id=\"PPAuthInfo\"><ps:BinaryVersion>5</ps:BinaryVersion><ps:HostingApp>Managed IDCRL</ps:HostingApp></ps:AuthInfo><wsse:Security>{0}</wsse:Security></S:Header><S:Body><wst:RequestSecurityToken xmlns:wst=\"http://schemas.xmlsoap.org/ws/2005/02/trust\" Id=\"RST0\"><wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType><wsp:AppliesTo><wsa:EndpointReference><wsa:Address>{1}</wsa:Address></wsa:EndpointReference></wsp:AppliesTo><wsp:PolicyReference URI=\"MBI\"></wsp:PolicyReference></wst:RequestSecurityToken></S:Body></S:Envelope>".format(saml_assertion,mso_domain)
	headers = {'Content-Type':'application/soap+xml'}

	response_object = requests.post(default_stsauth_url,headers=headers,data=post_body)
	response_text = response_object.text
	start_keyword = "<wsse:BinarySecurityToken Id=\"Compact0\" xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">"
	stop_keyword = "</wst:RequestedSecurityToken>"
	start_index = response_text.find(start_keyword)
	stop_index = response_text.find(stop_keyword)
	
	binary_token = response_text[(start_index+len(start_keyword)):(stop_index+2-len(stop_keyword))]

	return binary_token

# Step 4:
# Get SPOIDCRL cookie from tenant's SPO authentication page by POSTing binary security token
def retrieve_spoidcrl_cookie(binary_token):
	binary_token_header = "BPOSIDCRL {0}".format(binary_token)
	spo_uri = "https://redacted.sharepoint.com/_vti_bin/idcrl.svc/"
	headers = {'Authorization':binary_token_header,'X-IDCRL_ACCEPTED':'t','User-Agent':''}
	
	response_object = requests.get(spo_uri,headers=headers)
	spoidcrl_cookie = response_object.cookies

	return spoidcrl_cookie

# Step 5:
# Get target file from SPO by GETting with SPOIDCRL for authentication
def retrieve_target_file(spoidcrl_cookie):
	source_url = "redacted"
	destination_dir = "redacted"

	response_object = requests.get(source_url,cookies=spoidcrl_cookie)
	file_content = response_object.content

	f = open(destination_dir,'wb')
	f.write(file_content)
	f.close()

###							###
###  FUNCTION CALLS	###
###							###

username = sys.argv[1]
password = sys.argv[2]
mso_domain = "redacted.sharepoint.com"

custom_stsauth_url = retrieve_custom_stsauth_url(username)
saml_assertion = retrieve_saml_assertion(custom_stsauth_url,username,password)
binary_token = retrieve_binary_token(saml_assertion,mso_domain)
spoidcrl_cookie = retrieve_spoidcrl_cookie(binary_token)
retrieve_target_file(spoidcrl_cookie)