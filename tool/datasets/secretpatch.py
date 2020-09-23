#!/usr/bin/env python3
import re
import shutil
from collections import Callable

import pandas as pd

from pathlib import Path
from urllib import request
from zipfile import ZipFile
from distutils.dir_util import copy_tree

from utils.data_structs import DataPaths
from utils.decorators.filter import c_code, equal_adds_dels, one_line_changes
from utils.decorators.io import load, save
from utils.decorators.transform import dict_to_frame, parse_patch_file
from utils.patch_record import PatchRecord

cve_pattern_secret = r'CVE-(\d{4})-(\d{4,7})\.([\w\-]+)\.([\w\-]+)\.([0-9a-f]{5,40})'


@parse_patch_file
def transform_columns(**record):
    match = re.search(cve_pattern_secret, record["patch_file"].stem)
    match.group(4), match.group(5), match.group(1), match.group(2)

    return {'project': match.group(4), 'commit': match.group(5), 'year': match.group(1), 'number': match.group(2)}


class SecretPatch:
    def __init__(self, name: str, paths: DataPaths):
        self.name = name
        self.paths = paths
        self.collected_path = self.paths.collected / Path(self.name)
        self.transformed = self.paths.transformed / Path(self.name + '.pkl')

    def collect(self, source: str):
        out_path = self.paths.collected / Path(self.name)
        out_file = source.split("/")[-1]
        out_file_path = out_path / Path(out_file)
        out_path.mkdir(parents=True, exist_ok=True)
        print(f"Downloading from source {source}")
        request.urlretrieve(source, str(out_file_path))

        with ZipFile(str(out_file_path), 'r') as zf:
            print("Extracting zip.")
            zf.extractall(path=out_path)

        extract_path = str(out_path / Path("cleaned"))
        trash_path = str(out_path / Path("__MACOSX"))
        print(f"Moving files from {extract_path} to {out_path}")
        copy_tree(src=extract_path, dst=str(out_path))
        shutil.rmtree(extract_path)
        shutil.rmtree(trash_path)
        out_file_path.unlink()

    @save
    @dict_to_frame
    def transform(self, path: Path):
        data = []

        for file in self.collected_path.iterdir():
            record = {"patch_file": file, 'name': '', 'lang': ''}
            patch_record_args = transform_columns(**record)
            patch_record = PatchRecord(**patch_record_args)

            if not patch_record.has_patch():
                continue

            patch_records = patch_record.to_dict()
            data.extend(patch_records)

        return data

    @save
    @one_line_changes
    @equal_adds_dels
    @c_code
    @load
    def filter(self, path: Path):
        print(f"Filtering {self.name}")
        return self.transformed
