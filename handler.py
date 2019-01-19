import json
import config


env = 'dev'
config = config.get_config()[env]

def getCorsHeaders():
    return {
        "X-Requested-With": '*',
        "Access-Control-Allow-Headers": 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,x-requested-with',
        "Access-Control-Allow-Origin": '*',
        "Access-Control-Allow-Methods": 'POST,GET,OPTIONS'
    }

def makeProxyResponse(httpCode, headers, bodyModel):
    return {
            "isBase64Encoded": False,
            "statusCode": httpCode,
            "headers": headers,
            "body": json.dumps(bodyModel)
        }

def getInfo(event, context):
    return makeProxyResponse(200, getCorsHeaders(), {'yatza':'message successfully recieved'})
