from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.conf import settings
import os
from .models import UspsServices, UserDetails
import xml.etree.ElementTree as ET
from xml.dom import minidom
from xml.dom.minidom import parse, parseString, Document
from pathlib import Path
import time
import json
import requests
from django.contrib import messages

# Logout Function


def logout(request):
    # Redirect to the logout endpoint of Azure Web
    print("Logout Initiated")
    return HttpResponseRedirect("/.auth/logout")

# Main Init Function


def init(request):
    # Populate User Details
    user_data,other_att,object_id = get_user_name(request)
    # print(user_data)
    if not hasattr(user_data, "userName") or user_data.userName == "":
        # If User Details not available, Return to Login Page
        print("Not Authenticated. Redirecting to Login Page")
        return HttpResponseRedirect(user_data.loginUrl)
    else:
        # If User Details are available, Populate InstanceName variable
        user_data.instanceName = str(settings.ENVIRONMENT).upper()

        # If User Details are available, read XML Services File and generate Links
        xmldoc = ET.parse(os.path.join(
            os.path.dirname(__file__), 'services.xml'))
        root = xmldoc.getroot()
        serviceList = []
        try:
            supplieraccess_list = []
            for item in other_att:
                f = {}
                # item.split("|")[0].upper()
                f['app_name']=item.split("|")[0]
                f['sup_id']=item.split("|")[-3]
                f['sup_name']=item.split("|")[3]
                f['uid'] = item.split("|")[1]     
                d = f
                # print(d)
                supplieraccess_list.append(d)
            print(supplieraccess_list)    
        except:
            messages.success(request,'You are not authorized to use the services of Business Process Gateway. Please contact your manager for assistance.')                
        for child in root:
            service = UspsServices()        
            service.serviceCode = child.attrib['serviceCode'].upper()
            service.serviceName = child.attrib['serviceName']
            service.serviceDescription = child.attrib['serviceDescription']
            # Service URL is generated based upon ENVIRONMENT variable
            service.url = child.attrib[str((settings.ENVIRONMENT)+'url').upper()]            
            service.logoutUrl = service.url + child.attrib['LOGOUTURL']
            
            # If ServiceCode (from xml) is available in User's ILE Access List, show the service
            try:
                
                for item in user_data.ileAccessList:

                    if "FA" == item.split("|")[0].upper(): 
                        service.accessFlag = True  
                        break    
                    elif "ILERPT" == item.split("|")[0].upper(): 
                        service.accessFlag = True  
                        break    
                    else :
                        service.accessFlag = False
            except Exception as e:
                print(e)
                service.accessFlag = False
            service.pendingActivationFlag = int(os.environ.get('BPG_LINKS_DISABLED',0)) if 'BPG_LINKS_DISABLED' in os.environ else 0
            
            if service.pendingActivationFlag == 0:
                try:
                    for item in user_data.ileAccessList:
                        print("item",item)
                        if service.serviceCode + "|" + "TRUE"==item.split("|")[0] + "|" + item.split("|")[-1]:
                            service.pendingActivationFlag = 0
                            break
                        else:
                            service.pendingActivationFlag = 1
                except Exception as e:
                    print(e)
                    # Do nothing since pending flag is already initialized from Environment
                    pass            
            service.id = child.attrib['id']                
            serviceList.append(service)
        serviceList.append(user_data)    
    return render(request, 'bpgtemplate.html',{"object_id":object_id,"SupplieracessList":supplieraccess_list,"serviceList":serviceList})
        

# Get User Details        
def get_user_name(request):
    # For Testing in Local Only. Will be removed before deployment to Prod
    user_details = UserDetails()
    user_details.userName = "Test"
    # user_details.ileAccessList = ['FA|TRUE', 'ILERPT|TRUE', 'FA|TRUE', 'ILERPT|TRUE']
    # user_details.ileAccessList = ['FA|TRUE','ILERPT|FALSE']
    # user_details.ileAccessList = [{'typ': 'ILE_Alternate_UserID_1', 'val': 'FA|UC00000011|000406395|MAXWAY|TRUE'}, {'typ': 'ILE_Alternate_UserID_2', 'val': 'ILERPT|UC00000011|000406395|MAXWAY|TRUE'}, {'typ': 'ILE_Alternate_UserID_3', 'val': 'FA|UC10000011|001105117|10 ROADS|TRUE'}, {'typ': 'ILE_Alternate_UserID_4', 'val': 'ILERPT|UC10000011|001105117|10 ROADS|TRUE'}]
    user_details.loginUrl="aaa"
    access_token="Dsdds"
    user_claim = [
      {
        "typ": "aud",
        "val": "f39a2a78-9a34-47b6-9639-f82650127a22"
      },
      {
        "typ": "iss",
        "val": "https://login.microsoftonline.com/f9aa5788-eb33-4a49-8ad0-76101910cac3/v2.0"
      },
      {
        "typ": "iat",
        "val": "1671891461"
      },
      {
        "typ": "nbf",
        "val": "1671891461"
      },
      {
        "typ": "exp",
        "val": "1671895361"
      },
      {
        "typ": "aio",
        "val": "AZQAa/8TAAAAHuccRJ9scskHtBI3+uridRXGwY3x9vW1d+CeOaFnD+AuUxvTp+P+t009Lgnj/LqbBMRvcwO0dAudm/0f2EH3Ki255YzsovCQzOIPfF+D3VBdVCKsve620yhbHcol1O4BVgLe2ssYoo7E6fvg0d3P5WuZHWMSoUo09/isqOJoflJnGoUkbdHO+ROGClXH8xYe"
      },
      {
        "typ": "c_hash",
        "val": "RftF1bqXXuafgvnXWi19kA"
      },
      {
        "typ": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        "val": "ILEUser4@hotmail.com"
      },
      {
        "typ": "http://schemas.microsoft.com/identity/claims/identityprovider",
        "val": "https://sts.windows.net/9188040d-6c67-4c5b-b112-36a304b66dad/"
      },
      {
        "typ": "nonce",
        "val": "600c20f57c9d426a8cf011f41e511d68_20221224142729"
      },
      {
        "typ": "http://schemas.microsoft.com/identity/claims/objectidentifier",
        "val": "273ae15e-f08e-48ee-9102-7858f55d00ae"
      },
      {
        "typ": "preferred_username",
        "val": "ILEUser4@hotmail.com"
      },
      {
        "typ": "rh",
        "val": "0.ARgAiFeq-TPrSUqK0HYQGRDKw3gqmvM0mrZHljn4JlASeiIYAPY."
      },
      {
        "typ": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier",
        "val": "K5rG5rzgNzdLqFWadcV5LpRSWfVhKeHRQVODOCvlPAA"
      },
      {
        "typ": "http://schemas.microsoft.com/identity/claims/tenantid",
        "val": "f9aa5788-eb33-4a49-8ad0-76101910cac3"
      },
      {
        "typ": "uti",
        "val": "qFdFIwrEKUecMVB0t7SIAA"
      },
      {
        "typ": "ver",
        "val": "2.0"
      },
      {
        "typ": "ILE_Alternate_UserID_1",
        "val": "FA|UC00000011|000406395|MAXWAY|TRUE"
      },
      {
        "typ": "ILE_Alternate_UserID_2",
        "val": "ILERPT|UC00000011|000406395|MAXWAY|TRUE"
      },
      {
        "typ": "ILE_Alternate_UserID_3",
        "val": "FA|UC10000011|001105117|10 ROADS|TRUE"
      },
      {
        "typ": "ILE_Alternate_UserID_4",
        "val": "ILERPT|UC10000011|001105117|10 ROADS|TRUE"
      }
    ]
    l,other_att,object_id= get_access_list(user_claim)
    print("obj",object_id)
    user_details.ileAccessList = l
    return(user_details,other_att,object_id)
    
    try:
        user_details = UserDetails()
        # Get JSON containing Access Token
        auth_response = get_access_token(request)[0]
        access_token=auth_response["access_token"]         
        
        # Call Graph API with the access token
        graph_response = call_graph (access_token)
        # Generate UserName to be shown in page
        if "givenName" in graph_response:
            user_details.userName=graph_response["givenName"]
            if "mail" in graph_response:
                user_details.userName = user_details.userName + " (" + graph_response["mail"] + ")"
        # Generate a list of user-claims user has access to
        print("auth_response",auth_response)
        print("before_user_ileAccessList",user_details.ileAccessList)
        user_details.ileAccessList,other_att,object_id=get_access_list (auth_response['user_claims'])
        print(user_details.ileAccessList,other_att,object_id)
        # Generate Login URL
        user_details.loginUrl = get_login_url (auth_response['user_claims'])
        print("user_details",user_details)
        #user_ileAccessList [{'typ': 'ILE_Alternate_UserID_1', 'val': 'FA|UC00000011|000406395|MAXWAY|TRUE'}, {'typ': 'ILE_Alternate_UserID_2', 'val': 'ILERPT|UC00000011|000406395|MAXWAY|TRUE'}, {'typ': 'ILE_Alternate_UserID_3', 'val': 'FA|UC10000011|001105117|10 ROADS|TRUE'}, {'typ': 'ILE_Alternate_UserID_4', 'val': 'ILERPT|UC10000011|001105117|10 ROADS|TRUE'}]

        print("user_ileAccessList",user_details.ileAccessList)
        return (user_details,other_att,object_id)
        
    except Exception as e:
        print ("get_user_name Exception")
        print (e)
        user_details.userName=""
        access_token = ""
        access_token = ""
        object_id = ""
        return (user_details,access_token,object_id)

# Fetch Access Token for the validated user
def get_access_token(request):

    auth_url = request.scheme + "://" + os.environ.get('WEBSITE_HOSTNAME') +"/.auth/me"
    # print("AUTH URL"+auth_url)
    try:        
        cookie = request.COOKIES.get("AppServiceAuthSession")
        if cookie is not None:
            curSession = requests.Session() # all cookies received will be stored in the session object  

            # Pass Authentication Cookie to fetch access token
            response = curSession.get(auth_url,cookies=request.COOKIES)                
            auth_json = response.json()          
        return auth_json
    except Exception as e:
        print ("Inside get_access_token exception")
        print (e)

def call_graph(access_token):    
    # Call Graph API using access token
    response = requests.get("https://graph.microsoft.com/v1.0/me",headers={'Authorization': 'Bearer '+ access_token})
    graph_json = response.json()
    if not response.ok:        
        if "error" in graph_json:
            print(graph_json["error"]["code"])        
            print (response.status_code)
    return graph_json

# Generate a list of ILE claims user has access to    
def get_access_list(user_claims):
    ileAccessList=[]
    other_att = []
    try:
        for userclaims in user_claims:
            if userclaims['typ'] == "http://schemas.microsoft.com/identity/claims/objectidentifier":
                object_id = userclaims['val']
                print(userclaims['val'])
            if userclaims['typ'].startswith('ILE'):
                try:
                    appname = userclaims['val'].split("|")[0].upper()
                    appstatus = userclaims['val'].split("|")[4].upper()
                    
                except Exception as e:
                    appstatus = ""
                other_att.append(userclaims['val'])
                ileAccessList.append(appname + "|" + appstatus)
    except Exception as e:
        print ("get_access_list Exception")
        print (e)       
    return(ileAccessList,other_att,object_id)

# Generate a list of ILE claims user has access to    
def get_login_url(user_claims):
    base_url = "https://login.microsoftonline.com/"
    try:
        for userclaims in user_claims:
            if userclaims['typ'] == 'aud':
                client_id = userclaims['val']
            elif userclaims['typ'].endswith('tenantid'):
                tenant_id = userclaims['val']
            elif userclaims['typ'] == 'nonce':
                nonce = userclaims['val']
        login_url = base_url + tenant_id + "/oauth2/v2.0/authorize?response_type=code+id_token&client_id=" + client_id + "&scope=openid+profile+email&response_mode=form_post&nonce=" + nonce + "&state=redir%3D%252F"
    except Exception as e:
        print ("get_login_url Exception")
        print (e)       
    return(login_url)

from django.shortcuts import redirect

def update_user_details(request,user_id,object_id,app_name):
    print("app_name",app_name)
    print("object_id",object_id)
    print("user_id",user_id)
    url = 'https://login.microsoftonline.com/f9aa5788-eb33-4a49-8ad0-76101910cac3/oauth2/v2.0/token'
    
    req_body = {"client_secret":str(settings.CLIENT_SECRET),"client_id":str(settings.CLIENT_ID),"scope":"https://graph.microsoft.com/.default","grant_type":"client_credentials"}
    response = requests.post(url, data=req_body)
    print('send data')
    print(response.json())
    
    url2 = 'https://graph.microsoft.com/v1.0/users/{}'.format(object_id)
    req_body2 = {}
    k = str(settings.EXTENTION_USER_ID)+"_"+app_name+"_"+"Session_UserID"
    req_body2[k] = user_id
    print(req_body2)
    head = {'Authorization': 'Bearer  {}'.format(response.json()['access_token'])}
    response2 = requests.patch(url=url2, json=req_body2,headers=head)
    
    xmldoc = ET.parse(os.path.join(
            os.path.dirname(__file__), 'services.xml'))
    print(xmldoc)
    root = xmldoc.getroot()
    head2 = {
        'ConsistencyLevel':'eventual',
        'Authorization': 'Bearer  {}'.format(response.json()['access_token'])
    }
    response3 = requests.get(url=f'https://graph.microsoft.com/v1.0/users/{object_id}?$select=userType,userPrincipalName,extension_a05c0d9bb29f482f8f170eb6d040af5b_FA_Session_UserID',headers=head2)
    json_res = json.loads(response3.text)
    for i in range(0,9):
        if json_res['extension_a05c0d9bb29f482f8f170eb6d040af5b_FA_Session_UserID'] == user_id:
            break
        else:
            time.sleep(8)
            response3 = requests.get(url=f'https://graph.microsoft.com/v1.0/users/{object_id}?$select=userType,userPrincipalName,extension_a05c0d9bb29f482f8f170eb6d040af5b_FA_Session_UserID',headers=head2)
            json_res = json.loads(response3.text)
            
        
    for child in root:        
        sc = child.attrib['serviceCode'].upper()
        if app_name == sc:
            url = child.attrib[str((settings.ENVIRONMENT)+'url').upper()]     
            return redirect(url)        
    
    print('User Update Result')
    # return HttpResponse("user_updated", content_type='text/plain')
