import sys
from ArconSDK import ArconSDK


 
def get_sec(token,username,alias_name):
    try:
        arcon_sdk = ArconSDK(token)
        data = [{
        "UserName": username,
        "AliasName": alias_name ,
         "OpenForHours": 10  }]
        response = arcon_sdk.get_credential(data)
        if response:
            print("response:", response)
            return response
        else:
            print("Failed to obtain response")
 
    except Exception as ex:
        print("Exception occurred:", ex)
 
 
if __name__ == "__main__":
    token = sys.argv[1]
    username = sys.argv[2]
    alias_name = sys.argv[3]
    sec=get_sec(token,username,alias_name)
