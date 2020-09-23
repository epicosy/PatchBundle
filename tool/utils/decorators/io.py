#!/usr/bin/env python3
from functools import wraps
from typing import Callable

import pandas as pd


def save(method: Callable):
    @wraps(method)
    def _impl(*method_args, **method_kwargs):
        dataset = method(*method_args, **method_kwargs).reset_index(drop=True)
        try:
            dataset.to_pickle(path=method_kwargs['path'])
            return dataset
        except KeyError as ke:
            print(f"No save path to for frame:{ke}")
    return _impl


def load(func):
    @wraps(func)
    def _impl(*args, **kwargs):
        path = func(*args, **kwargs)
        print(f"Loading dataset from {path}")

        if path.exists():
            return pd.read_pickle(filepath_or_buffer=str(path))
        return None
    return _impl

