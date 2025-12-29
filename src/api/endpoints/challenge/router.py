# -*- coding: utf-8 -*-

from fastapi import APIRouter, Request, HTTPException, Body, Depends, Query, Response
from fastapi.responses import JSONResponse, RedirectResponse

from api.core.constants import ErrorCodeEnum, ALPHANUM_HYPHEN_REGEX
from api.core.schemas import BaseResPM
from api.core.responses import BaseResponse
from api.core.exceptions import BaseHTTPException
from api.core.dependencies.auth import auth_api_key
from api.logger import logger

from .schemas import MinerInput, MinerOutput
from . import service


router = APIRouter(tags=["Challenge"])


@router.get(
    "/redirect",
    summary="Redirect device to dynamic challenge URL",
    description="This endpoint redirects a device to its dynamic session URL on the proxy.",
    response_class=Response,
)
def get_redirect(request: Request, device_id: int = Query(..., ge=0)):
    _request_id = request.state.request_id
    logger.info(f"[{_request_id}] - Redirecting device ID {device_id}...")

    try:
        _url = service.get_redirect_url(device_id=device_id)
        logger.success(f"[{_request_id}] - Redirecting device {device_id} to {_url}")
        
        # Return a 307 Redirect with "no-referrer" policy
        # This prevents the destination page (Miner JS) from seeing "device_id=X" in document.referrer
        return Response(
            status_code=307,
            headers={
                "Location": _url,
                "Referrer-Policy": "no-referrer"
            }
        )
    except Exception as e:
        logger.warning(f"[{_request_id}] - Failed to redirect device {device_id}: {e}")
        # Fallback or error page could go here, but raising 404 is standard if session not active
        raise HTTPException(status_code=404, detail="Session not active or device not found")


@router.get(
    "/task",
    summary="Get task",
    description="This endpoint returns the task for the miner.",
    response_class=JSONResponse,
    response_model=MinerInput,
)
def get_task(request: Request):

    _request_id = request.state.request_id
    logger.info(f"[{_request_id}] - Getting task...")

    _miner_input: MinerInput
    try:
        _miner_input = service.get_task()

        logger.success(f"[{_request_id}] - Successfully got the task.")
    except HTTPException:
        raise
    except Exception:
        logger.exception(
            f"[{_request_id}] - Failed to get task!",
        )
        raise BaseHTTPException(
            error_enum=ErrorCodeEnum.INTERNAL_SERVER_ERROR,
            message="Failed to get task!",
        )

    return _miner_input


@router.post(
    "/score",
    summary="Score",
    description="This endpoint score miner output.",
    response_class=JSONResponse,
    responses={422: {}},
)
def post_score(request: Request, miner_input: MinerInput, miner_output: MinerOutput):

    _request_id = request.state.request_id
    logger.info(f"[{_request_id}] - Scoring the miner output...")

    _score: float = 0.0
    try:
        _score = service.score(request_id=_request_id, miner_output=miner_output)
        logger.success(
            f"[{_request_id}] - Successfully scored the miner output: {_score}"
        )
    except HTTPException:
        raise
    except Exception:
        logger.exception(f"[{_request_id}] - Failed to score the miner output!")
        raise BaseHTTPException(
            error_enum=ErrorCodeEnum.INTERNAL_SERVER_ERROR,
            message="Failed to score the miner output!",
        )

    return _score


@router.post(
    "/_fingerprint",
    summary="Set device fingerprint",
    description="This endpoint receives the device fingerprint from the DFP proxy server.",
    response_model=BaseResPM,
    responses={401: {}, 422: {}},
    dependencies=[Depends(auth_api_key)],
)
def post_fingerprint(
    request: Request,
    order_id: int = Body(..., ge=0, lt=1000000, examples=[0]),
    fingerprint: str = Body(
        ..., min_length=2, max_length=128, pattern=ALPHANUM_HYPHEN_REGEX
    ),
):
    _request_id = request.state.request_id
    logger.info(
        f"[{_request_id}] - Setting device fingerprint as {{'order_id': {order_id}, 'fingerprint': '{fingerprint}'}} ..."
    )

    try:
        service.set_fingerprint(
            order_id=order_id,
            fingerprint=fingerprint,
        )

        logger.success(
            f"[{_request_id}] - Successfully set device fingerprint as {{'order_id': {order_id}, 'fingerprint': '{fingerprint}'}}."
        )
    except HTTPException:
        raise
    except Exception:
        logger.exception(
            f"[{_request_id}] - Failed to set device fingerprint as {{'order_id': {order_id}, 'fingerprint': '{fingerprint}'}}!"
        )
        raise BaseHTTPException(
            error_enum=ErrorCodeEnum.INTERNAL_SERVER_ERROR,
            message="Failed to set device fingerprint!",
        )

    _response = BaseResponse(
        request=request, message="Successfully set device fingerprint."
    )
    return _response


__all__ = ["router"]
