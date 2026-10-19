"""Small source-only project used by contract/e2e tests."""
from vulnerable_pkg import Client
from vulnerable_pkg import connect as aliased_connect


def routed_call():
    return aliased_connect()


def instance_call():
    client = Client()
    return client.send()


def dynamic_call(name):
    return getattr(Client, name)()


def transitive_call():
    from parent_pkg import wrapper
    return wrapper.call()
