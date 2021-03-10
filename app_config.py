import os

##################################################################################################
##  TODO:  IMPLEMENT CLIENT_ID, CLIENT_SECRET, & NGROK_SECRET AS ENV VARIABLES                  ##
##  https://flask.palletsprojects.com/en/1.1.x/config/#configuring-from-environment-variables   ##
##    CLIENT_SECRET = os.getenv("CLIENT_SECRET")                                                ##
##    if not CLIENT_SECRET:                                                                     ##
##        raise ValueError("Need to define CLIENT_SECRET environment variable")                 ##
##################################################################################################

NGROK_SECRET = "NGROK-SECRET"
CLIENT_ID = "CLIENT-ID"
CLIENT_SECRET = "CLIENT-SECRET"

##################################################################################################
##################################################################################################

AUTHORITY = "https://login.microsoftonline.com/common"

REDIRECT_PATH = "/getAToken"
##  Will be used to form an absolute URL
##  Must match your app's redirect_uri set in AAD

##  Microsoft Graph API endpoints from Graph Explorer
##  https://developer.microsoft.com/en-us/graph/graph-explorer
ENDPOINT = 'https://graph.microsoft.com/beta/me/presence'  # This resource requires no admin consent
SUBSCRIPTIONS_ENDPOINT = 'https://graph.microsoft.com/v1.0/subscriptions/'

##  You can find the proper permission (scope) names from this document
##  https://docs.microsoft.com/en-us/graph/permissions-reference
SCOPE = ["Presence.Read.All"]

SESSION_TYPE = "filesystem"  # So token cache will be stored in server-side session
