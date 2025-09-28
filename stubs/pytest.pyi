# stubs/pytest.pyi
from typing import Any, TypeVar, overload

# stubs/pytest.pyi
from typing import ContextManager
from types import TracebackType

E = TypeVar('E', bound=BaseException)

class ExceptionInfo:
    value: BaseException
    type: type[BaseException]
    typename: str
    traceback: TracebackType

    def match(self, regexp: str) -> bool: ...

def raises(
    expected_exception: type[E],
    *args: Any, # pyright: ignore[reportAny, reportExplicitAny]
    match: str | None = None
) -> ContextManager[ExceptionInfo]: ...

T = TypeVar('T')

class MonkeyPatch:
    @overload
    def setattr(self, target: str, value: Any, raising: bool = ...) -> None: ... # pyright: ignore[reportAny, reportExplicitAny]
    @overload
    def setattr(self, target: object, name: str, value: Any, raising: bool = ...) -> None: ... # pyright: ignore[reportAny, reportExplicitAny]

