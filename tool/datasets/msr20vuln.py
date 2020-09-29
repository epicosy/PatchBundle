#!/usr/bin/env python3

import urllib.request as request
import pandas as pd

from pathlib import Path

from utils.data_structs import DataPaths
from utils.patch_record import PatchRecord

# Decorators
from utils.decorators.transform import dict_to_frame
from utils.decorators.io import load, save
from utils.decorators.filter import c_code, equal_adds_dels, one_line_changes
from utils.decorators.msr20 import changes_to_patches, parse_year_number


@parse_year_number
@changes_to_patches
def transform_columns(**record):
    return {'project': record['project'], 'commit': record['commit_id']}


class MSR20Vuln:
    def __init__(self, name: str, paths: DataPaths):
        self.name = name
        self.mapping = {}
        self.paths = paths
        self.collected_path = self.paths.collected / Path(self.name)
        self.transformed = self.paths.transformed / Path(self.name + '.pkl')

    def collect(self, source: str):
        self.collected_path.mkdir(parents=True, exist_ok=True)
        out_file_path = self.collected_path / Path("msr20.csv")
        print(f"Downloading from source {source}")
        request.urlretrieve(source, str(out_file_path))

    @save
    @dict_to_frame
    def transform(self, path: Path):
        data = []
        MSR20 = self.collected_path / Path("msr20.csv")
        commit_dataset = pd.read_csv(str(MSR20))
        records = commit_dataset.to_dict(orient='records')

        for record in records:
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
