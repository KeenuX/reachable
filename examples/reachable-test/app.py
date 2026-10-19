"""Small sample project for reachable's first real-project scan."""
from demo_pkg import vulnerable as reachable_vulnerable


def main():
    # This call is proven reachable from the __main__ entry point.
    return reachable_vulnerable("sample-input")


if __name__ == "__main__":
    main()
