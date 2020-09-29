#!/usr/bin/env python3
from pathlib import Path

import pandas as pd

from functools import wraps
from typing import Callable, Union
from utils.code_parser import Patch
from .code import clean_code_file


frame_columns = ['project', 'commit', 'cve_year', 'cve_number', 'name', 'lang', 'hunk', 'additions', 'deletions',
                 'hunk_name']


def dict_to_frame(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        data = func(*args, **kwargs)
        frame = pd.DataFrame.from_dict(data)
        print(f"Hunks count: {len(frame)}")
        frame.drop_duplicates(subset="hunk", keep=False, inplace=True)
        print(f"Unique hunks count: {len(frame)}")
        return frame
    return wrapper


def create_patch(func: Callable):
    @wraps(func)
    def wrapper_create_patch(*args, **kwargs):
        lines = func(*args, **kwargs)
        if lines:
            patch = Patch(name=kwargs['name'], lang=kwargs['lang'])
            for line in lines:
                patch(line)
            return patch
        return None
    return wrapper_create_patch


@create_patch
@clean_code_file
def file_to_patch(patch_file: Union[str, Path], name: str = '', lang: str = '', **kwargs):
    if isinstance(patch_file, str):
        patch_file = Path(patch_file)

    if patch_file.exists():
        return patch_file

    return None


def parse_patch_file(func: Callable):
    @wraps(func)
    def wrapper_parse_patch_file(*args, **kwargs):
        patch_record_args = func(*args, **kwargs)

        patch = file_to_patch(**kwargs)
        patch_record_args.update({'patches': [patch]})

        return patch_record_args

    return wrapper_parse_patch_file
