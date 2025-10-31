import base64
import ipaddress
import os
import ssl
import psutil
import pyotp
import requests
import json
import re
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
from datetime import datetime
from requests.auth import HTTPBasicAuth 
import inspect
import sys
import hashlib
from requests.auth import HTTPProxyAuth
from requests.adapters import HTTPAdapter
import platform
import subprocess

class ArconSDK:
    SdkAppType = "Python SDK"
    SdkKey = "pgMs8z0diRevoPuEiK0AEOQKDFvzkZq+3nWvqfO8RHc="
    SdkIV = "1Io6+nrJteHztE5KK9RUaQ=="
    # SdkAppType = "C# SDK"
    # SdkKey = "4wYLKjQ710xwgOqYIqZk1+6iOmMFJ3TdqmmhMlUprIY="
    # SdkIV = "etIibG29TiD5xxwuUmLGVQ=="

    class HttpRequestDetails:
        def __init__(self):
            self.ID = 0
            self.url = ''
            self.userName = ''
            self.ARC_XWD = ''
            self.methodName = ''
            self.methodType = ''
            self.contenttype = ''
            self.postData = ''
            self.token = ''
            self.port = ''
            self.response = ''

    class NIntFileContent:
        def __init__(self):
            self.AppUsername = ''
            self.AppType = ''
            self.AppName = ''
            self.EncXWD = ''
            self.IP_MAC = []
            self.InfoEncKey = ''
            self.gatewayURL = ''
   
    ##logging.basicConfig(level=##logging.INFO, filename="ArconSDK.log",filemode="a")
    def __init__(self, TokenFilePath):
        self.sdkTokenFilePath = TokenFilePath
        self.sdkIsVerified = False
        self.bearerToken = ""
        self.bearerValid = None
        self.sdkAppName = ""
        self.gatewayURL = ""
        self.digitalVaultUser = {}

        try:
            with open(TokenFilePath, 'r') as file:
                ni_fileContent_str = file.readline()
            
            if self.verify_content(ni_fileContent_str):
                #print("ArconSDK object created.")
                #logging.info("ArconSDK object created.")
                self.sdkIsVerified = True
                gateway_url = self.digitalVaultUser.get("GatewayUrl", "")
                if not gateway_url.endswith("/"):
                    self.digitalVaultUser["GatewayUrl"] = gateway_url + "/"
                self.client = self.HttpRequestDetails()
                self.client.url = self.digitalVaultUser["GatewayUrl"]
            else:
                print("Download the correct file." )
                #logging.warning("Download the correct file")
                self.dispose()
                raise Exception("Download the correct file.")
        except Exception as ex:
            # print("Failed to create object")
            # print(f"Exception: {str(ex)}")
            ##logging.error(f"Failed to create object: {str(ex)}")
            self.dispose()
            self.digitalVaultUser = {}
            raise Exception("Download the correct file.")
    
    def dispose(self):
        self.digitalVaultUser = {}
        self.bearerToken = ""
        self.sdkIsVerified = False
        print("Class was Disposed.")
        ##logging.warning("Class was Disposed")
   
    def verify_content(self, ni_fileContent_str):
        try:
           
            ni_fileContent_str = self.decrypt_content(True, ni_fileContent_str)
            #print(f"Decrypted file content: {ni_fileContent_str}")
            self.digitalVaultUser = json.loads(ni_fileContent_str)
            #print("Successfully loaded JSON content.")
            #print("verify ")
            if self.digitalVaultUser["AppType"].lower() != self.SdkAppType.lower():
                print(f"Initial SDK app name: {self.sdkAppName}")
                return False
            #print("check filename ")
            appfile = __file__  # Change this line accordingly
            self.sdkAppName = os.path.splitext(os.path.basename(appfile))[0]
            sdkname2=self.sdkAppName
            frame = inspect.currentframe()
            caller_file = None
            #print(f"Initial SDK app name: {self.sdkAppName}")
            # Go back through the stack frames until we find the caller file
            while frame:
                caller_file = frame.f_code.co_filename
                if caller_file != __file__:
                    break
                frame = frame.f_back

            if caller_file:
                caller_file_base = os.path.splitext(os.path.basename(caller_file))[0]  # Extract base name without extension
                #print(caller_file_base ,"H")
                self.sdkAppName = caller_file_base

                #print(self.sdkAppName)
                # if is_imported(caller_file_base):
                    # print(f"{self.sdkAppName}.py is imported in {caller_file_base}")
                    # self.sdkAppName = caller_file_base  # Store caller file name without extension in sdkAppName
                # else:
                    # print(f"{self.sdkAppName}.py is not imported in {caller_file_base}")
            

            if sdkname2 not in sys.modules:
                #print("Fail to verify sdkname")
                return False

            if self.digitalVaultUser["AppName"].lower() != self.sdkAppName.lower():
                print("Fail Appname" , self.sdkAppName )
                return False
                
            publisher_name = self.get_publisher_name(self.sdkAppName)
            if self.digitalVaultUser["Publisher"].lower() != "na" and self.digitalVaultUser['Publisher'].lower() != publisher_name.lower():
                print("Failed for publisher name ")
                return False

            if self.digitalVaultUser.get("FingerPrint"):  # Use .get() to safely check if "FingerPrint" exists
                is_valid = self.verify_system_info()
                print(is_valid)
                print(self.digitalVaultUser["FingerPrint"])
                if is_valid != self.digitalVaultUser["FingerPrint"]:
                    return False
              

            is_valid_ip_mac = self.verify_ip_mac(self.digitalVaultUser["IP_MAC"])

            if not is_valid_ip_mac:
                return False
            
        except Exception as ex:
            self.digitalVaultUser = {}
            return False
    
        return True 
    
    def is_imported(module_name):
        return module_name in sys.modules
    
    def get_bios_id(self):
        try:
            if os.name == 'nt':  # Windows
                import wmi
                c = wmi.WMI()
                for bios in c.Win32_BIOS():
                    return bios.SerialNumber
            return "Unknown"
        except Exception as ex:
            return f"Error: {str(ex)}"
    
    def get_cpu_id(self):
        try:
            if os.name == 'nt':  # Windows
                import wmi
                c = wmi.WMI()
                for processor in c.Win32_Processor():
                    return processor.ProcessorId
            return "Unknown"
        except Exception as ex:
            return f"Error: {str(ex)}"
        
    def generate_sha256_hash(self,input_string):
        # Create a new sha256 hash object
        sha256_hash = hashlib.sha256()
        # Update the hash object with the bytes of the input string
        sha256_hash.update(input_string.encode('utf-8'))
        # Get the hexadecimal representation of the hash
        return sha256_hash.hexdigest()
    
    
    def get_hostname(self):
        return platform.node()  

    def is_ip_address_in_range(self, ip_address, network_address, prefix_length):
            if ip_address.version != network_address.version:
                return False

            ip_bytes = ip_address.packed
            network_bytes = network_address.packed
            num_full_bytes = prefix_length // 8
            remaining_bits = prefix_length % 8

            for i in range(num_full_bytes):
                if ip_bytes[i] != network_bytes[i]:
                    return False

            if remaining_bits > 0:
                mask = 0xFF00 >> remaining_bits
                if (ip_bytes[num_full_bytes] & mask) != (network_bytes[num_full_bytes] & mask):
                    return False

            return True
    
    def get_publisher_name(self, process_name):
        try:
            process_info = os.stat(process_name)
            company_name = process_info.st_company_name
            return company_name
        except Exception as e:
          
            return "Unknown"    
    
    def generate_totp(self,secret_key: str) -> str:
        # Create a TOTP object using the secret key
        totp = pyotp.TOTP(secret_key)

        # Generate and return the TOTP code (6-digit code by default)
        return totp.now()
    
    def verify_ip_mac(self, ip_mac_list):
        if len(ip_mac_list) == 0:
            return True
        for network_interface in psutil.net_if_addrs():
            for ip_info in psutil.net_if_addrs()[network_interface]:
                for entry in ip_mac_list:
                    if not entry:
                        return True

                    ip_address = entry[0]
                    if '/' in entry[0] and entry[1] == "0":
                        parts = entry[0].split('/')
                        prefix_length = int(parts[1])
                        network_address = ipaddress.IPv4Address(parts[0])
                        if self.is_ip_address_in_range(ip_info.address, network_address, prefix_length):
                            return True

                    if ip_info.address == ip_address:
                        mac_address = entry[1]
                        if mac_address == "0":
                            return True
                        else:
                            mac_address = mac_address
                            physical_address = None

                            for addr in psutil.net_if_addrs()[network_interface]:
                                if addr.family == psutil.AF_LINK:
                                    physical_address = addr.address.replace(":", "").lower()
                                    break
                            
                            if physical_address.lower() == mac_address.lower():
                                return True
                            else:
                                return False

        return False  
    
    def encrypt_content(self, is_fk, content, key=""):
        sdk_key = ""
        sdk_iv = ""

        if is_fk:
            key = base64.b64decode(self.SdkKey)
            iv = base64.b64decode(self.SdkIV)
        else:
            key = base64.b64decode(key)
            iv = base64.b64decode(self.SdkIV)

        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Pad the content to be a multiple of 16 bytes
        content_padded = content + (16 - len(content) % 16) * chr(16 - len(content) % 16)

        encrypted_bytes = cipher.encrypt(content_padded.encode('utf-8'))
        enc_str = base64.b64encode(encrypted_bytes).decode('utf-8')

        return enc_str

    def decrypt_content(self, is_fk, content, key=""):
        sdk_key = ""
        sdk_iv = ""

        if is_fk:
            key = base64.b64decode(self.SdkKey)
            iv = base64.b64decode(self.SdkIV)
        else:
            key = base64.b64decode(key)
            iv = base64.b64decode(self.SdkIV)

        cipher = AES.new(key, AES.MODE_CBC, iv)

        encrypted_bytes = base64.b64decode(content)
        decrypted_bytes = cipher.decrypt(encrypted_bytes)

        # Remove padding
        padding_length = decrypted_bytes[-1]
        decrypted_content = decrypted_bytes[:-padding_length].decode('utf-8')

        return decrypted_content
    def key(self) -> str:
        app_key = json.dumps({
            "EncXWD": self.digitalVaultUser["EncXWD"],
            "AppName": self.digitalVaultUser["AppName"]
        })

        Data = json.dumps({
            "AppUserName": self.encrypt_content(True, self.digitalVaultUser["AppUsername"]),
            "AppTypeName": "Python SDK",
            "AppKey": self.encrypt_content(False, app_key, self.digitalVaultUser["InfoEncKey"]),
            "Validator": None if not self.digitalVaultUser.get("FingerPrint") else self.verify_system_info(),
            "TOTP": None if not self.digitalVaultUser.get("TOTPKey") else self.generate_totp(self.digitalVaultUser["TOTPKey"])
   
        })

        # Convert to Base64
        base64String = base64.b64encode(Data.encode('utf-8')).decode('utf-8')
        return base64String

    def cert_validation(self, server_url, development):
        if server_url.upper().startswith("HTTPS"):
            session = requests.Session()
            session.mount(server_url, HTTPAdapter())
            if development:
                # SSL verification should be enabled, remove verify=False unless testing
                session.verify = True  # Ensure SSL verification is done for security


    def create_http_request(self, obj_http_request_details, is_token=False):
        # Construct the full URL
        if obj_http_request_details.url.endswith("/"):
            server_url = obj_http_request_details.url + obj_http_request_details.methodName
        else:
            server_url = obj_http_request_details.url + "/" + obj_http_request_details.methodName
        
        # Normalize the URL to ensure no double slashes
        server_url = re.sub(r'(https?://[^/]+)//*', r'\1/', server_url)
        
        # Set up headers
        headers = {
            
            'Content-Type': obj_http_request_details.contenttype,
            'Accept': obj_http_request_details.contenttype,
            'User-Agent': 'Mozilla/5.0',  # Simplified User-Agent for cross-platform compatibility
           
        }

        # Include the token if provided
        if obj_http_request_details.token:
            headers['Authorization'] = f"Bearer {obj_http_request_details.token}"

        # Additional headers if not using token
        if not is_token:
            headers['ArcSecResBody'] = '1'
            headers['AppTypeName'] = base64.b64encode(self.digitalVaultUser["AppType"].encode()).decode('utf-8')

        # # Prepare SSL context for older SSL/TLS versions (optional)
        # ssl_context = ssl.create_default_context()
        # ssl_context.set_ciphers("DEFAULT@SECLEVEL=1")  # To work with older SSL/TLS versions
        # ssl_context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
        # self.cert_validation(server_url, True)
        
        # Prepare the POST data
        data = obj_http_request_details.postData
        
        # Return the request object
        return requests.Request("POST", server_url, data=data, headers=headers)
    def response_post_data(self, request):
            data = ''
            try:
                # Setup the request session
                session = requests.Session()

                # Check if Proxy is configured and needed
                if self.digitalVaultUser.get("Proxy"):  # Check if Proxy setting exists
                    # Get the proxy details from the digitalVaultUser dictionary
                    proxy_url = f"{self.digitalVaultUser['ProxyIP']}:{self.digitalVaultUser['ProxyPort']}"
                    
                    # Prepare the proxy dictionary (no need to include 'http' and 'https' twice)
                    proxies = {
                        'http': f'http://{self.digitalVaultUser["AppUsername"]}:{self.key()}@{proxy_url}',
                        'https': f'http://{self.digitalVaultUser["AppUsername"]}:{self.key()}@{proxy_url}'
                    }

                    # Apply the proxy settings to the session
                    session.proxies = proxies

                    # Debugging: Print the proxy settings and credentials for troubleshooting
                    # print(f"Proxy URL: {proxy_url}")
                    # print(f"Proxy Username: {self.digitalVaultUser['AppUsername']}")
                    # print(f"Proxy Password: {self.key()}")

                    # Set up the proxy authentication using HTTPProxyAuth
                    proxy_auth = HTTPProxyAuth(self.digitalVaultUser["AppUsername"], self.key())
                    session.auth = proxy_auth  # Apply the authentication to the session

            
                    # print("No Proxy settings found.")
                
                # Debugging: Print the session object to verify proxy configuration
                # print(f"Session Proxies: {session.proxies}")
                # print(f"Session Auth: {session.auth}")

                # Send the POST request through the proxy (with SSL verification disabled for testing)
                response = session.send(request.prepare(), verify=False)

                # Check for HTTP errors
                response.raise_for_status()

                # Return the response content as text
                data = response.text
            except requests.exceptions.HTTPError as http_err:

                # Handle different HTTP errors
                if http_err.response is not None:
                    if http_err.response.status_code == 401:  # Unauthorized
                        data = "Error: Authentication failed"
                    elif http_err.response.status_code == 400:  # Bad Request
                        data = f"Error: Bad Request {http_err}"
                    else:
                        data = f"Error: {http_err}"
                else:
                    data = f"Error: {http_err}"
            except Exception as e:
                # General error handling
                data = f"Error: {e}"

            return data
        
    def get_bearer_token(self):
        self.bearerToken = ''
        bearer_client = self.HttpRequestDetails()
        bearer_client.url = self.digitalVaultUser["GatewayUrl"]
        bearer_client.methodName = 'DV/api/sdk/GetTokenByKey'  #dont start with '/'
        bearer_client.methodType = 'POST'
        bearer_client.contenttype = 'application/json'

        app_key = json.dumps({
            "EncXWD": self.digitalVaultUser["EncXWD"],
            "AppName": self.digitalVaultUser["AppName"]
        })

        bearer_client.postData = json.dumps({
            "AppUserName": self.encrypt_content(True, self.digitalVaultUser["AppUsername"]),
            "AppTypeName": "Python SDK",
            "AppKey": self.encrypt_content(False, app_key, self.digitalVaultUser["InfoEncKey"]),
            "Validator": None if not self.digitalVaultUser.get("FingerPrint") else self.verify_system_info(),
        })
        #print(bearer_client.postData)
        bearer_api_response = self.response_post_data(self.create_http_request(bearer_client, True))
        print("Bearer API Call", bearer_api_response)
        response_obj = json.loads(bearer_api_response)
        is_resp_success = response_obj.get("Success",False)
        
        if not is_resp_success or not bearer_api_response:
            self.bearerToken = ''
        else:
            result= response_obj.get("Result",{})
            self.bearerToken = result.get("accessToken","")
            self.bearerValid =result.get("expiresIn","")
            # self.bearerValid = datetime.strptime(expires_in_str, "%Y-%m-%dT%H:%M:%S")            
        self.client.token = self.bearerToken
    
    def get_credential(self, data):
        api_method_type = "POST"
        api_content_type = "JSON"
        response_items = None
        if self.digitalVaultUser.get("FingerPrint"):
             if data and len(data) > 0:
                  data[0]['Validator'] = self.verify_system_info() 
        post_data = json.dumps(data)
        method_name = "DV/api/SDK/GetTargetDevicePassKey"   #dont start with '/'
        method_type, content_type, pam_api_response = "", "", ""

        try:
            if api_content_type == "JSON":
                content_type = "application/json"
            elif api_content_type == "XML":
                content_type = "application/xml"
            else:
                content_type = ""

            ##logging.info("API request made:")
            if self.bearerValid is None or self.bearerValid < datetime.now():
                self.get_bearer_token()
        except Exception as ex:
            print("Error at get_credential")
            print(f"Exception: {str(ex)}")
            self.digitalVaultUser = {}
            ##logging.error(f"Error at get_credential Exception: {str(ex)}")
            return ""

        try:
            if api_method_type.upper() == "GET":
                self.client.methodName = method_name
                self.client.methodType = "GET"
                self.client.contenttype = content_type
                pam_api_response = self.response_post_data(self.create_http_request(self.client))
            elif api_method_type.upper() == "POST":
                self.client.methodName = method_name
                self.client.postData = post_data
                self.client.methodType = "POST"
                self.client.contenttype = content_type
                pam_api_response = self.response_post_data(self.create_http_request(self.client))
            else:
                raise NotImplementedError()
            is_resp_success = json.loads(pam_api_response).get("Message") == "Success"

            if not is_resp_success or not pam_api_response:
                # print("Error at get_credential")
                ##logging.warning("Error at get_credential")
                self.digitalVaultUser = {}
                return ""
            else:
                pam_api_response_json = json.loads(pam_api_response)
                service_details_decrypt = pam_api_response_json["Result"]
                service_details_decrypt = self.decrypt_content(False, service_details_decrypt, self.digitalVaultUser["InfoEncKey"])
                service_details_decrypt = service_details_decrypt.replace("\\", "")
                response_items = json.loads(service_details_decrypt.strip('\\').strip('"'))

            return response_items
        except Exception as ex:
            print("Error at get_credential")
            print(f"Exception: {str(ex)}")
            self.digitalVaultUser = {}
            ##logging.error(f"Error at get_credential Exception: {str(ex)}")
            return ""
    
    def verify_system_info(self) -> str:
        # Retrieve the actual system values
        os_type = self.get_operating_system_type()
        if os_type == "Windows":
            system_cpu_id =self.get_cpu_id()
            system_hostname = self.get_hostname()
            system_bios_id = self.get_bios_id()
            uuid = self.windows_uuid()
            # Create the string to hash
            system_info = f"CPU ID: {system_cpu_id} OS Version: {os_type} Hostname: {system_hostname} BIOS Serial Number: {system_bios_id} UUID: {uuid}"
            # Generate the SHA256 hash (assuming generate_sha256_hash returns a hex string)
            sha256_hash = self.generate_sha256_hash(system_info)  # This should be in hex format or converted to hex
        elif os_type == "Linux":
            hostname = self.get_hostname()
            uuid = self.get_linux_uuid()
            os_version = self.get_linux_distro_name()
            linux_value = f"Hostname: {hostname} UUID: {uuid} OS Base Version: {os_version}"

            # with open("OGCOnten.txt", "w") as file:
            #     file.write(linux_value)

            sha256_hash = self.generate_sha256_hash(linux_value)
            # with open("ArconFingerPrint.txt", "w") as file:
            #     file.write(sha256_hash)

        elif os_type == "MacOS":
            hostname = self.get_hostname()
            uuid = self.get_mac_uuid()
            os_version = self.get_mac_os_version()
            mac_value = f"Hostname: {hostname} UUID: {uuid} OS Version: {os_version}"

            # with open("OGCOnten.txt", "w") as file:
            #     file.write(mac_value)

            sha256_hash = self.generate_sha256_hash(mac_value)
            # with open("ArconFingerPrint.txt", "w") as file:
            #     file.write(sha256_hash)


        return sha256_hash
    def get_operating_system_type(self):
        system_name = platform.system().lower()
        if 'windows' in system_name:
            return "Windows"
        elif 'linux' in system_name:
            return "Linux"
        elif 'darwin' in system_name:
            return "MacOS"
        return "Unknown"
    def get_linux_distro_name(self):
        try:
            with open('/etc/os-release') as f:
                for line in f:
                    if line.startswith("NAME="):
                        return line.split('=')[1].strip().strip('"')
            return "Linux distribution name not found"
        except Exception as ex:
            return f"Error: {str(ex)}"

    def get_linux_uuid(self):
        try:
            with open("/etc/machine-id") as f:
                return f.read().strip()
        except Exception as ex:
            return f"Error reading UUID: {str(ex)}"
    
    def get_mac_uuid(self):
        try:
            result = subprocess.run(['system_profiler', 'SPHardwareDataType'], stdout=subprocess.PIPE)
            output = result.stdout.decode()
            for line in output.split('\n'):
                if "Hardware UUID" in line:
                    return line.split(":")[1].strip()
            return "Unknown"
        except Exception as ex:
            return f"Error reading UUID: {str(ex)}"
    def get_mac_os_version(self):
        try:
            result = subprocess.run(['sw_vers', '-productVersion'], stdout=subprocess.PIPE)
            return result.stdout.decode().strip()
        except Exception as ex:
            return f"Error reading macOS version: {str(ex)}"
    def windows_uuid(self):
        try:
            # Initialize the WMI client
            import wmi
            c = wmi.WMI()
            for item in c.Win32_ComputerSystemProduct():
                return item.UUID if item.UUID else "UUID not found"
        except Exception as e:
            return f"An error occurred: {str(e)}"
                
# Example usage:
# sdk_instance = ArconSDK("path/to/token_file.txt")
# if sdk_instance.sdkIsVerified:
#     response = sdk_instance.get_credential(ArconSDK.ApiMethodType.GET, ArconSDK.ApiContentType.JSON)
#     print(response)


