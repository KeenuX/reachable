"""Offline demo source: imports are intentionally unavailable at runtime."""

import dynamiclib
from dangerouslib import Client
from dangerouslib import parse as parse_alias


client = Client()


def reachable_by_alias(value: str) -> str:
    return parse_alias(value)


def reachable_by_instance(value: str) -> str:
    return client.load(value)


def dynamic_lookup(value: str) -> str:
    loader = getattr(dynamiclib, "load")
    return loader(value)


if __name__ == "__main__":
    reachable_by_alias("demo")
    reachable_by_instance("demo")
