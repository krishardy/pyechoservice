import logging
import json

import azure.functions as func


def main(req: func.HttpRequest) -> func.HttpResponse:
    try:
        output = {
            "method": req.method,
            "url": req.url,
            #"headers": {k, req.headers[k] for k in req.headers},
            "params": req.params,
            #"route_params": str(req.route_params),
            #"body_type": str(req.body_type),
            #"body": str(req.body)
        }
        return func.HttpResponse(json.dumps(output), status_code=200)
    except Exception as e:
        return func.HttpResponse(str(e), status_code = 501)
    """
    logging.info('Python HTTP trigger function processed a request.')

    name = req.params.get('name')
    if not name:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            name = req_body.get('name')

    if name:
        return func.HttpResponse(f"Hello, {name}. This HTTP triggered function executed successfully.")
    else:
        return func.HttpResponse(
             "This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response.",
             status_code=200
        )
    """
