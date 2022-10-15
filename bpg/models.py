from django.db import models

# Model to capture various services to be shown on the page
class UspsServices:
    id : int
    serviceName : str    
    serviceCode : str
    serviceDescription : str
    url : str
    logoutUrl : str   
    accessFlag : bool
    pendingActivationFlag : bool

# Model to capture User details
class UserDetails:
    uid : int
    userName : str
    ileAccessList = []
    loginUrl : str
    instanceName: str 