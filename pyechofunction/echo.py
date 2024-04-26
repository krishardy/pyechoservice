import logging

import azure.functions as func

bp = func.Blueprint()

@bp.route(route="echo")
def echo(req: func.HttpRequest) -> func.HttpResponse:
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
