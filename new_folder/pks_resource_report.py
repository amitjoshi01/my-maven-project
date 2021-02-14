# Author : Amit Joshi Feb-21
import os, sys
import subprocess
import requests
import json
import urllib3
from encrypter  import encrypt_with_rsa, decrypt_with_rsa
#from  encrypter import encrypt_with_rsa, decrypt_with_rsa

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'scripts'))

urllib3.disable_warnings()

#Function to login to pks
def pks_login(auth_file, rsa_key_file):
    global pks_api_bearer_token
    global pks_api_headers_1
    global pks_api_headers_2
    global pks_api_clusters
    global pks_api_clusterdetails

    #with open(auth_file) as json_file:
    pks_auth_file_decrypted_string = decrypt_with_rsa(auth_file, rsa_key_file)
    pks_auth_vars_json = json.loads(pks_auth_file_decrypted_string)

    pks_user = pks_auth_vars_json['pks_user']
    pks_pass = pks_auth_vars_json['pks_pass']
    pks_auth_url = pks_auth_vars_json['pks_auth_url']
    pks_api_clusters = pks_auth_vars_json['pks_api_clusters']
    pks_api_clusterdetails = pks_auth_vars_json['pks_api_clusterdetails']

    pks_auth_headers = {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}
    pks_auth_data = {"grant_type": "client_credentials"}

    session = requests.Session()
    session.auth = (pks_user, pks_pass)

    response = session.post(pks_auth_url, headers=pks_auth_headers, data=pks_auth_data, verify=False)
    if response.status_code == 200:
        json_data = json.loads(response.content.decode("utf-8"))
        pks_api_bearer_token = json_data["access_token"]
        pks_api_headers_1 = {
            "Accept": "application/json",
            "Authorization": "Bearer %s" % pks_api_bearer_token,
            }
        pks_api_headers_2 = {
            "Authorization": "Bearer %s" % pks_api_bearer_token,
            "Content-Type": "application/json"
            }


def get_cluster_by_name(cluster_name):
    response = requests.get(pks_api_clusterdetails+cluster_name, headers=pks_api_headers_1, verify=False)
    if response.status_code == 200:
        json_data = json.loads(response.content.decode("utf-8"))
        return json_data["uuid"]
    return None

def bosh_login(bosh_auth_file, ca_cert: str, bosh_rsa_key_file):

    bosh_auth_file_decrypted_string = decrypt_with_rsa(bosh_auth_file, bosh_rsa_key_file)
    bosh_auth_vars_json = json.loads(bosh_auth_file_decrypted_string)

    bosh_username = bosh_auth_vars_json['bosh_username']
    bosh_password = bosh_auth_vars_json['bosh_password']
    bosh_environment = bosh_auth_vars_json['bosh_environment']

    os.environ['BOSH_ENVIRONMENT'] = bosh_environment

    if "-----BEGIN CERTIFICATE-----" in ca_cert:
        os.environ['BOSH_CA_CERT'] = ca_cert
    else:
        with open(ca_cert) as ca_file:
            os.environ['BOSH_CA_CERT'] = ca_file.read()
    bosh_env = os.environ['BOSH_ENVIRONMENT']
    os.system(f'echo {bosh_username}"\n"{bosh_password}"\n"|bosh login')




def get_deployment_vms(deployment_name):
    temp_file = subprocess.Popen([f'mktemp'], stdout=subprocess.PIPE).communicate()[0].decode('utf-8').replace('\n', '')
    os.system(f'bosh -d {deployment_name} vms --vitals > {temp_file}')
    resource_usage_params = []
    list_of_resource_usage_params =[]
    with open(temp_file) as in_file:
        j = 0
        for d in in_file.readlines():
            resource_usage_params = []
            for i in [4,3,5,11,12,13,14]:
                resource_usage_params.append(d.split("\t")[i])
            list_of_resource_usage_params.append(resource_usage_params)
    os.system(f'rm {temp_file}')
    return list_of_resource_usage_params

if __name__ == '__main__':
    path = os.getcwd()
    environment_name = sys.argv[1]
    auth_file = path+"/pks_encry_"+environment_name+".conf"
    rsa_key_file = path+"/pks_key_"+environment_name+".pem"
    bosh_auth_file = path+"/bosh_encry_"+environment_name+".conf"
    bosh_rsa_key_file = path+"/bosh_key_"+environment_name+".pem"

    ca = path+"/tlab_bosh_ca_cert_"+environment_name+".pem"
    pks_login(auth_file, rsa_key_file)
    response = requests.get(pks_api_clusters, headers=pks_api_headers_1, verify=False)
    pks_cluster_details_dictionary = {}
    pks_cluster_dictionary = {}
    f = open(path+"/pks_resource_utility_report_"+environment_name+".txt", "w")

    if response.status_code == 200:
        json_data = json.loads(response.content.decode("utf-8"))
        for index in range(len(json_data)):
            for key,value in json_data[index].items():
                if key == "name":
                    uuid = get_cluster_by_name(value)
                    bosh_login(bosh_auth_file, ca, bosh_rsa_key_file)
                    resource_usage_param_list = get_deployment_vms(f'service-instance_{uuid}')
                    pks_cluster_dictionary = {value:resource_usage_param_list}
            pks_cluster_details_dictionary.update(pks_cluster_dictionary)

    for names,lists in pks_cluster_details_dictionary.items():
        f.write(f"Cluster Name: {names}- \n")
        f.write(f"{'VM CID':<50}{'IP Address':<20}{'VM Type':<20}{'CPU User':<20}{'CPU sys':<20}{'CPU Wait':<20}{'Memory Usage':<20}")
        f.write("\n")
        for index in range(len(lists)):
            f.write(f'{lists[index][0]:<50}{lists[index][1]:<20}{lists[index][2]:<20}{lists[index][3]:<20}{lists[index][4]:<20}{lists[index][5]:<20}{lists[index][6]:<20}')
            f.write("\n")
        f.write("\n")
