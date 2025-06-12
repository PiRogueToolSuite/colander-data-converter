import pytest

from colander_data_converter.base.common import Singleton


class Configuration(metaclass=Singleton):
    def __init__(self, value):
        self.value = value


@pytest.mark.isolate()
def test_creates_single_instance_for_multiple_calls():
    config1 = Configuration(value=1)
    config2 = Configuration(value=2)
    assert config1 is config2


@pytest.mark.isolate()
def test_preserves_initialization_of_first_instance():
    config1 = Configuration(value=10)
    config2 = Configuration(value=20)
    assert config1.value == 10
    assert config2.value == 10


@pytest.mark.isolate()
def test_allows_different_singletons_for_different_classes():
    class A(metaclass=Singleton):
        pass

    class B(metaclass=Singleton):
        pass

    a1 = A()
    a2 = A()
    b1 = B()
    b2 = B()
    assert a1 is a2
    assert b1 is b2
    assert a1 is not b1


@pytest.mark.isolate()
def test_supports_init_with_args_and_kwargs():
    class Example(metaclass=Singleton):
        def __init__(self, x, y=0):
            self.x = x
            self.y = y

    e1 = Example(5, y=7)
    e2 = Example(10, y=20)
    assert e1 is e2
    assert e1.x == 5
    assert e1.y == 7
