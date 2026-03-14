# -*- coding: utf-8 -*-

import os
import sys
import json
import logging
import pathlib
import requests
from typing import Union, List

from fastapi import FastAPI, Body, HTTPException
from fastapi.responses import JSONResponse
from data_types import MinerInput, MinerOutput


logger = logging.getLogger(__name__)
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    datefmt="%Y-%m-%d %H:%M:%S %z",
    format="[%(asctime)s | %(levelname)s | %(filename)s:%(lineno)d]: %(message)s",
)


app = FastAPI()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/solve", response_model=MinerOutput)
def solve(miner_input: MinerInput = Body(...)) -> MinerOutput:

    logger.info(f"Retrieving fingerprinter.js and related files...")
    _miner_output: MinerOutput
    try:
        _src_dir = pathlib.Path(__file__).parent.resolve()
        _fingerprinter_dir = _src_dir / "fingerprinter"

        _fingerprinter_js_path = str(_fingerprinter_dir / "fingerprinter.js")
        _fingerprinter_js = (
            "function detectDriver() { localStorage.setItem('driver', 'Chrome'); }"
        )
        with open(_fingerprinter_js_path, "r") as _fingerprinter_js_file:
            _fingerprinter_js = _fingerprinter_js_file.read()

        _miner_output = MinerOutput(
            fingerprinter_js=_fingerprinter_js,
        )
        logger.info(f"Successfully retrieved fingerprinter.js and related files.")
    except Exception as err:
        logger.error(f"Failed to retrieve fingerprinter.js and related files: {err}")
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve fingerprinter.js and related files.",
        )

    return _miner_output


__all__ = ["app"]
