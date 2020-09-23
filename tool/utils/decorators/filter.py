#!/usr/bin/env python3
import functools
from typing import Callable


def reset_index(func: Callable):
    """Filters dataset by one line changes in the hunk."""
    @functools.wraps(func)
    def wrapper_reset_index(*args, **kwargs):
        dataset = func(*args, **kwargs)
        return dataset.reset_index(drop=True)
    return wrapper_reset_index


def c_code(func: Callable):
    """Filters dataset by hunks in c code."""
    @functools.wraps(func)
    @reset_index
    def wrapper_c_code(*args, **kwargs):
        dataset = func(*args, **kwargs)
        c_code_frame = dataset[dataset.apply(lambda row: row['lang'] in ['.c', '.h'], axis=1)]
        return c_code_frame
    return wrapper_c_code


def equal_adds_dels(func: Callable):
    """Filters dataset by equal additions and deletions in the hunk."""
    @functools.wraps(func)
    @reset_index
    def wrapper_equal_adds_dels(*args, **kwargs):
        dataset = func(*args, **kwargs)
        eq_frame = dataset.loc[dataset["additions"] == dataset["deletions"]]
        return eq_frame
    return wrapper_equal_adds_dels


def one_line_changes(func: Callable):
    """Filters dataset by one line changes in the hunk."""
    @functools.wraps(func)
    @reset_index
    def wrapper_one_line_changes(*args, **kwargs):
        dataset = func(*args, **kwargs)
        one_frame = dataset.loc[dataset["additions"] == 1]
        return one_frame
    return wrapper_one_line_changes

