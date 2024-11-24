
from flask import Flask, jsonify
import json
import os
import logging
import requests
import jsonify
from datetime import datetime
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse


# load_dotenv() for sensitive information
# Load environment variables from .env file
load_dotenv()
bearer_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVTZWN1cml0eU5hbWUiOiIxZWNtdmZpd2lxIiwiZGF0YVBsYW5lTmFtZXNwYWNlIjoiYWMxZWNtdmZpd2lxIiwiY3JuIjoiY3JuOnYxOmF3czpwdWJsaWM6YXBwY29ubmVjdDp1cy1lYXN0LTE6c3ViLzIwMjMwOTA4LTE3NDktNTE1Mi02MGYyLTNkMmNlYmI0M2FjMjoyMDIzMDkwOC0xNzUwLTI2NjUtODBkOC05YjVmODU5ZGIwNzM6OiIsImp3dFZlcmlmeUVudiI6InAtdmlyLWMxIiwiaWF0IjoxNzEzMjc4NjU3LCJleHAiOjE3MTMzMjE4NTcsImF1ZCI6ImFwcGNvbm5lY3QuaWJtY2xvdWQuY29tIiwiaXNzIjoiYXBwY29ubmVjdCIsInN1YiI6IjFlY212Zml3aXEifQ.R4WNWXkSjF4DYtZGPRB5y675UHiT3slCByrAlpNUbgAUwxoBKLs903caolLtcJ9XIQ8_sxll1c6jqcERsO4q5vdgzyVH1xXrZ7f63k4qnTJNYIfgLJh12a3XIW1gdDsZ2vj42inLQfFn9Way6GnmesdY9kb8_L3HvXRaCefUncJRfgQH83GnQ-pPFthJFE7Q10vXbKor8VHQnZpuyKsmiceVwt2cM--zDIz_iQlpbYAyUYtImfLDogwvxFbIz-YXjMo0RFHm5eQBzhk_V4UMvscG17JAO4JIhtreTIDnd3G0K3sjn-ZSljyqnIsVcc7mR5kKV-FnPJAUeDCgEfaAtKqOBi3lWTNWjSuv6At2RAfCDoNerqlXP05clSXNG3ReBu75jLZBufphVAUA8i1LlJF5kMEkDSNl5UzeDdl3YbDT6dm5pz9BKOY5j-GGTx7ZGJkSvL2APh8_9o5aX7WSMQNosiWZzzxbHLEFnAHcnulJsUQtu8uJPPcJ9q39CFD2JHtZMuvC7Iz4-s85P8da_uwirvMp699R0AUv3hoT2WILtluU-5-IGS5tM9ImuWbVevksKREWFI4s4h0EI_8N9LZexbVTEzcPlRQ6gd7-sMCL7WDJpTWA-FOUm6n1UuZ3OOsOzSft82ZcVX_aH9UpwD4YMJv_nnj2O7cNLCV7S3g"
IBM_CLIENT_ID = os.getenv("IBM_CLIENT_ID")
os.getenv("IBM_CLIENT_ID")
IBM_CLIENT_SECRET = os.getenv("IBM_CLIENT_SECRET")
IBM_INSTANCE_ID= os.getenv("IBM_INSTANCE_ID")
API_KEY = {
        "apiKey": os.getenv("API_KEY")
    }

# #####################################################
# Environment Variables
# #####################################################
HTTP_SERVER = 'https://api.p-vir-c1.appconnect.automation.ibm.com'
REQEST_VERSION = '/api/v1'
# #####################################################
# Configure Logging
# #####################################################
logging.basicConfig(
    level=logging.INFO,  # Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    format="%(asctime)s - %(name)s -  %(module)s - %(funcName)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("app.log"),  # Log to a file
        logging.StreamHandler()  # Log to the console
    ]
)

# #####################################################
# Create a logger object
# #####################################################
logger = logging.getLogger(__name__)

# #####################################################
# Load paramters Initialize global variables
# #####################################################
execution_parameters = {}
last_modified_time = None


with open("params.json", "r") as file:
    params = json.load(file)
logger.info("Parameters Loaded: %s", params)
# Application setup

app = FastAPI()

logger.info("Starting the application")

#
# Default execution path returns the current version of the API interfaces
# 
@app.get("/")
async def root():
    logger.info("APP Connect Iterface API V1.0 Running")
    return {"message": "APP Connect Iterface API V1.0"}
#
# Get the token needed to execute all app connect management API calls
#
@app.get("/token")
async def token():
   
    # URL of the API endpoint
    url = f"{HTTP_SERVER}{REQEST_VERSION}/tokens"
    
    # Headers for the request
    headers = {
        "X-IBM-Client-Id": "58326c7f188e2985cd070c4361c95665",
        "X-IBM-Client-Secret": "27e7fe3cc950979620cb0dc72a0f997b",
        "accept": "application/json",
        "content-type": "application/json",
        "x-ibm-instance-id": "1ecmvfiwiq",
        "Authorization": "Bearer YOUR_BEARER_TOKEN",  # Replace with the actual token
        "Cookie": 'X-Contour-Session-Affinity="6751cdb0e3f16dce"' # Optional: Include if required
    }


    # Make the API call
    response = make_api_call(url, headers, API_KEY)


    # Print response details
    logger.debug("Response: %s", response)
    logger.debug("Access Token: %s", response['data']['access_token'])

    return { "token" : response['data']['access_token']}

@app.get("/getRuntimeConfig/{runtimeId}")
async def getRuntimeConfig(runtimeId: str):
    logger.info("getRuntimeConfig: %s", runtimeId)

    # URL of the API endpoint
    url = f"{HTTP_SERVER}{REQEST_VERSION}/integration-runtimes/{runtimeId}"
    # Headers for the request
    headers = await get_headers() 

    # Make the API call
    # response = make_api_call(url, headers, API_KEY)
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        config = response.json()
        logger.debug("Response: %s", config)
        logger.debug("Replicas: %s", config['spec']['replicas'] )

        return   { "status" : "Success", 
                  "data" : config,
                  "http_status": response.status_code  # Optional
                 } 
    else:
        logger.error("Error: %s", response.status_code)
        error_message = response.json() 
        logger.error("Error: %s", error_message)
        return {
                "status": "ERROR",
                "message": "Error getting runtime configuration",
                "details": error_message, 
                "http_status": response.status_code
        }                 
    

@app.get("/ShutdownIR/{runtimeId}")
async def ShutdownIR(runtimeId: str):
    logger.info("ShutdownIR: %s", runtimeId)

    # Get the runtime configuration
    config = await getRuntimeConfig(runtimeId)
    logger.info("getRuntimeConfig status: %s",config["status"])  

    if config["status"] == "ERROR":
        logger.error("Error getting runtime configuration: %s", config)
        return { "status" : "ERROR",
                 "message" : "Error getting runtime configuration",
                 "http_status": config['http_status'],
                 "data" : runtimeId
                }
    
    if config['data']['spec']['replicas'] == 0:
        return { "status" : "Info",
                 "message" : "Runtime already shutdown",
                 "http_status": 200,
                 "data" : config['data']  # Optional
                }
    
    # todo: May need to add addition checks on the status of the IR to see if updates can be made

    
    # #####################################################
    # Now ready to change the replicas field in the configuration to 0
    # #####################################################
    # Headers for the request
    headers = await get_headers()
    # URL of the API endpoint
    url = f"{HTTP_SERVER}{REQEST_VERSION}/integration-runtimes/{runtimeId}" 
    # Update the configuration
    config['data']['spec']['replicas'] = 0
    # Make the API call
    response = requests.put(url, headers=headers, json=config['data'])
    # Handle the response
    if response.status_code == 200:
        logger.info("Success ShutdownIR: %s",runtimeId )
        return { "status" : "Success", 
                 "message" : "Runtime successfully shutdown",
                 "http_status": response.status_code,
                 "data" : response.json()  # Optional
                }
    else:
        logger.error("Error runtimeId: %s", response.status_code)
        return {
                "status": "ERROR",
                "message": "Error shutting down runtime",
                "details": response.text, 
                "http_status": response.status_code
        }


@app.get("/StartUpIR/{runtimeId}")
async def StartUpIR(runtimeId: str):
    logger.info("ShutdownIR: %s", runtimeId)

    # Get the runtime configuration
    config = await getRuntimeConfig(runtimeId)
    logger.info("getRuntimeConfig status: %s",config["status"])  

    if config["status"] == "ERROR":
        return { "status" : "ERROR",
                 "message" : "Error getting runtime configuration",
                 "http_status": 500,
                 "data" : runtimeId  # Optional
                }
    
    # #####################################################
    # Now ready to change the replicas field in the configuration to 
    # configured value in execution parms
    # #####################################################
    # Headers for the request
    headers = await get_headers()
    # URL of the API endpoint
    url = f"{HTTP_SERVER}{REQEST_VERSION}/integration-runtimes/{runtimeId}" 
    # Update the configuration
    irParams = await load_parameters_if_modified()
    logger.debug("IR Params: %s %s", irParams, type(irParams))
    
    try:
        replicas = irParams['IR'][runtimeId]['replicas']
    except KeyError as e:
        logger.error("KeyError: Missing key in the structure - %s Runtime: %s", e, runtimeId)
        raise HTTPException(status_code=404, detail=f"Missing key: {e}")      
    except TypeError as e:
        logger.error("TypeError: Invalid structure or unexpected type - %sRuntime: %s", e, runtimeId) 
        raise HTTPException(status_code=400, detail=f"Invalid structure: {e}")
    except Exception as e:
        logger.error("Unexpected error occurred: %sRuntime: %s", e, runtimeId)
        raise HTTPException(status_code=500, detail=f"Unexpected error: {e}")

    config['data']['spec']['replicas'] = replicas
    # Make the API call
    response = requests.put(url, headers=headers, json=config['data'])
    # Handle the response
    if response.status_code == 200:
        logger.info("Success StartUpIR: %s",runtimeId )
        return { "status" : "Success", 
                 "message" : "Runtime successfully started",
                 "http_status": response.status_code,
                 "data" : response.json()  # Optional
                }
    else:
        logger.error("Error runtimeId: %s", response.status_code)
        message = f"Error starting up runtime: {runtimeId}"
        return {
                "status": "ERROR",
                "message": message,
                "details": response.text, 
                "http_status": response.status_code
        }
    
# #####################################################
# List Runtimes
# #####################################################
@app.get("/listIR")
async def listIR():
    logger.info("ListIR")

    # URL of the API endpoint
    url = f"{HTTP_SERVER}{REQEST_VERSION}/integration-runtimes"
    # Headers for the request
    headers = await get_headers() 

    try:
        response = requests.get(url, headers=headers)
        integrationruntimes = response.json()['integrationRuntimes']
        runtimelist = []
        for runtime in integrationruntimes:
            #
            # Extract Infomation To return
            metadata_name = runtime.get("metadata", {}).get("name", "Unknown")
            spec_replicas = runtime.get("spec", {}).get("replicas", "Not Specified")
            status_info = runtime.get("status", {})
            available_replicas = status_info.get("availableReplicas", "Not Specified")
            phase = status_info.get("phase", "Not Specified")

            #
            # Get most recent condition
            conditions = status_info.get("conditions", [])
            # Extract conditions and sort by lastTransitionTime descending
            if conditions:
                conditions = sorted(
                    conditions, 
                    key=lambda c: datetime.strptime(c.get("lastTransitionTime", "1970-01-01T00:00:00Z"), "%Y-%m-%dT%H:%M:%SZ"), 
                    reverse=True
                    )
                # Take only the most recent condition
                most_recent_condition = conditions[0]
            else:
                most_recent_condition = None
            #    
            logger.debug("Runtime: %s %s %s %s %s", metadata_name, spec_replicas, available_replicas, phase, conditions)    
            #
            # Build the return structure
            runtime_details = {
            "name": metadata_name,
            "replicas": spec_replicas,
            "availableReplicas": available_replicas,
            "phase": status_info.get("phase", "Not Specified"),
            "conditions": most_recent_condition
            }
            #
            # Got all of the information, add to the list    
            runtimelist.append(runtime_details)
             
        return   { "status" : "Success", 
                  "data" : runtimelist,
                  "http_status": response.status_code  # Optional
                 }
    except requests.exceptions.RequestException as e:
        logger.error("Error: %s", response.status_code)
        error_message = response.json() 
        logger.error("Error: %s", error_message)
        return {
                "status": "ERROR",
                "message": "Error getting runtime configuration",
                "details": error_message, 
                "http_status": response.status_code
        }
# #####################################################        
# Make the API call
# #####################################################
def make_api_call(url: str, headers: dict, payload: dict = None) -> dict:
    """
    Generalized routine to perform an API call and return the response as a dictionary.

    Args:
        url (str): The API endpoint URL.
        headers (dict): The headers to include in the API call.
        payload (dict): Optional payload to send with the request.

        
        dict: The API response as a dictionary, or an error message if the call fails.
    """

    logger.info("Making API call to: %s", url)
    logger.debug("Headers: %s", headers)
    logger.debug("Payload: %s", payload)
    try:
        # Make the POST request
        response = requests.post(url, headers=headers, json=payload)

        # Check if the response is successful
        if 200 <= response.status_code < 300:
            logger.info("Successful response with status code: %d", response.status_code)
            try:
                return { "status" : "Success",
                    "status_code": response.status_code,
                    "data": response.json(),
                }
            except ValueError:
                logger.warning("Response is not JSON. Returning raw text.")
                return {
                    "status_code": response.status_code,
                    "data": response.text,
                }
        else:
            # Return an error message with the status code and response text
            logger.error("Request failed with status code: %d", response.status_code)
            return {
                "status": "ERROR",
                "message": f"Request failed with status code {response.status_code}",
                "details": response.text, 
                "http_status": response.status_code 
            }

    except requests.exceptions.RequestException as e:
        logger.critical("Exception occurred during API call: %s", str(e))
        # Handle any exceptions that occur during the API call
        return {
                "status": "ERROR",
                "message": f"Request failed with status code {response.status_code}",
                "error": "An exception occurred during the API call",
                "details": f"Exception occurred during API call: {str(e)}"
        }
    
# #####################################################
# Build headers to be used for requests
# #####################################################
async def get_headers(addl_headers: dict = None) -> dict:

    logger.debug("Getting headers for API call")
    # Get the token to use for the API Call 
    token_response =  await token()
    logger.debug("Token Response: %s", token_response['token'])
    bearer_token = token_response['token']  # Extract the token from the response
    logger.debug("Bearer Token: %s", bearer_token)


    headers = {
        "X-IBM-Client-Id": IBM_CLIENT_ID,
        "X-IBM-Client-Secret": IBM_CLIENT_SECRET,
        "accept": "application/json",
        "content-type": "application/json",
        "x-ibm-instance-id": IBM_INSTANCE_ID,
        "Authorization": f"Bearer {bearer_token}",
        "Cookie": 'X-Contour-Session-Affinity="6751cdb0e3f16dce"'
    } 

    logger.debug("Headers: %s", headers)
    return headers

# #####################################################
# Load paramters
# If the parameters file has changed, it is reloaded
# otherwise the existing parameters are returned
# #####################################################

    
async def load_parameters_if_modified() -> dict:
    """
    Checks if the file has been modified since the last load. 
    If so, reloads the parameters and updates the last modified time.

    Args:
        file_path (str): Path to the parameters file.

    Returns:
        dict: The current execution parameters.
    """
    logger.info("Loading parameters if modified")   
    global execution_parameters, last_modified_time
    file_path = "params.json"

    try:
        # Get the current last modified time of the file
        current_modified_time = os.stat(file_path).st_mtime

        # Check if the file has never been loaded or has been modified
        if last_modified_time is None or current_modified_time != last_modified_time:
            logger.info("Params File Changed: %s", last_modified_time)
            
            # Reload parameters from the file
            with open(file_path, "r") as file:
                execution_parameters = json.load(file)
            # Update the last modified time
            last_modified_time = current_modified_time
        else:
            logger.info(f"File {file_path} has not changed. Using cached parameters.")
    except FileNotFoundError:
        logger.error(f"Error: File {file_path} not found.")
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing JSON from file {file_path}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")

    return execution_parameters    