"""A deliberately uncertain dynamic-dispatch example."""
import dynamic_pkg


def dispatch(function_name, value):
    function = getattr(dynamic_pkg, function_name)
    return function(value)
