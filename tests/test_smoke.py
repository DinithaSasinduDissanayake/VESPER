"""Basic project health checks."""


def test_vesper_package_imports():
    import vesper

    assert vesper.__doc__
