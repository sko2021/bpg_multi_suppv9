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
    user_data,access_token,other_att = get_user_name(request)
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
    return render(request, 'bpgtemplate.html',{"access_token":access_token,"SupplieracessList":supplieraccess_list,"serviceList":serviceList})
        

# Get User Details        
def get_user_name(request):
    # For Testing in Local Only. Will be removed before deployment to Prod
    # user_details = UserDetails()
    # user_details.userName = "Test"
    # # user_details.ileAccessList = ['FA|TRUE', 'ILERPT|TRUE', 'FA|TRUE', 'ILERPT|TRUE']
    # # user_details.ileAccessList = ['FA|TRUE','ILERPT|FALSE']
    # # user_details.ileAccessList = [{'typ': 'ILE_Alternate_UserID_1', 'val': 'FA|UC00000011|000406395|MAXWAY|TRUE'}, {'typ': 'ILE_Alternate_UserID_2', 'val': 'ILERPT|UC00000011|000406395|MAXWAY|TRUE'}, {'typ': 'ILE_Alternate_UserID_3', 'val': 'FA|UC10000011|001105117|10 ROADS|TRUE'}, {'typ': 'ILE_Alternate_UserID_4', 'val': 'ILERPT|UC10000011|001105117|10 ROADS|TRUE'}]
    # user_details.loginUrl="aaa"
    # access_token="Dsdds"
    # user_claim = [{'typ': 'ILE_Alternate_UserID_1', 'val': 'FA|UC00000011|000406395|MAXWAY|TRUE'}, {'typ': 'ILE_Alternate_UserID_2', 'val': 'ILERPT|UC00000011|000406395|MAXWAY|TRUE'}, {'typ': 'ILE_Alternate_UserID_3', 'val': 'FA|UC10000011|001105117|10 ROADS|TRUE'}, {'typ': 'ILE_Alternate_UserID_4', 'val': 'ILERPT|UC10000011|001105117|10 ROADS|TRUE'}]
    # l,other_att = get_access_list(user_claim)
    # user_details.ileAccessList = l
    # return(user_details,access_token,other_att)
    
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
        user_details.ileAccessList,other_att=get_access_list (auth_response['user_claims'])

        # Generate Login URL
        user_details.loginUrl = get_login_url (auth_response['user_claims'])
        print("user_details",user_details)
        #user_ileAccessList [{'typ': 'ILE_Alternate_UserID_1', 'val': 'FA|UC00000011|000406395|MAXWAY|TRUE'}, {'typ': 'ILE_Alternate_UserID_2', 'val': 'ILERPT|UC00000011|000406395|MAXWAY|TRUE'}, {'typ': 'ILE_Alternate_UserID_3', 'val': 'FA|UC10000011|001105117|10 ROADS|TRUE'}, {'typ': 'ILE_Alternate_UserID_4', 'val': 'ILERPT|UC10000011|001105117|10 ROADS|TRUE'}]

        print("user_ileAccessList",user_details.ileAccessList)
        return (user_details,access_token,other_att)
        
    except Exception as e:
        print ("get_user_name Exception")
        print (e)
        user_details.userName=""
        return (user_details,access_token)

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
            if userclaims['typ'].startswith('ILE'):
                # print(userclaims['val'])
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
    return(ileAccessList,other_att)

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

def update_user_details(request, access_token,user_id,app_name):
    print("app",app_name)
    print('update_user_details user_id'+user_id+ access_token)
    url = 'https://graph.microsoft.com/v1.0/users/ILEUser4@hotmail.com'
    
    req_body = {}
    k = app_name+"_"+"Session_UserID"
    req_body[k] = user_id
    req_header = {'Content-Type':'application/json',
                  'Authorization':'Bearer ' + access_token}
    response = requests.patch(url, json=req_body,headers=req_header)
    print('send data')
    print(response)
    
    print('User Update Result')
    return HttpResponse(response, content_type='text/plain')