import sys
from ArconSDK import ArconSDK

def get_sec(token, username, alias_name):
    try:
        arcon_sdk = ArconSDK(token)
        data = [
            {"UserName": username, "AliasName": alias_name, "OpenForHours": 10}
        ]
        response = arcon_sdk.get_credential(data)
        if response:
            for server_info in response:
                print(f"ALIAS={server_info['aliasName']}")                
                print(f"IP={server_info['serverIp']}")
                print(f"USER={server_info['userName']}")            
                print(f"PASSWORD={server_info['password']}")
                #secrets = {"MY_SECRET": {server_info['password']}}
            	#print(f"##vso[task.setvariable variable={key};issecret=true]{server_info['password']}")
            #print("response:", response)
            #return response
        else:
            print("Failed to obtain response")

    except Exception as ex:
        print("Exception occurred:", ex)


if __name__ == "__main__":
    token = sys.argv[1]
    username = sys.argv[2]
    alias_name = sys.argv[3]
    get_sec(token, username, alias_name)
