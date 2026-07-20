from os import path
from pathlib import Path, PurePath
from typing import Union


class WorkspacePath:
    def __init__(self, workspace, p):
        self.workspace = workspace

        if not self.workspace.exists():
            raise ValueError("Workspace has not been created")

        # remove ../ and the like
        path_obj = PurePath(path.normpath(p))

        if not path_obj.is_absolute():
            raise ValueError(f"Workspace paths must be absolute ({path_obj} is not)")

        self.path = path_obj
        # Make all workspace path references relative to the workspace base directory
        self._real_path = Path(self.workspace.base_dir) / self._to_rel_path()

    @property
    def real_path(self):
        return self._real_path

    def exists(self):
        return self._real_path.exists()

    def open(self, **kwargs):
        return open(self._real_path, **kwargs)

    def mkdir(self):
        self._real_path.mkdir(exist_ok=True)

    def join(self, part):
        return WorkspacePath(self.workspace, self.path / part)

    def is_dir(self):
        return self._real_path.is_dir()

    def is_file(self):
        return self._real_path.is_file()

    def to_path(self):
        return self._real_path

    def __repr__(self):
        return "<WorkspacePath %s:%s>" % (self.workspace, self.path)

    def _to_rel_path(self):
        # remove the leading /
        return PurePath(*list(self.path.parts[1:]))


class Workspace:
    def __init__(self, base: Union[str, Path]):
        self._base_dir = base if isinstance(base, Path) else Path(base)

    def base_path(self):
        return self._base_dir

    def exists(self) -> bool:
        return self._base_dir.exists()

    def create(self) -> None:
        self._base_dir.mkdir(exist_ok=True)

    @property
    def base_dir(self) -> Path:
        return self._base_dir

    def path(self, p: Union[str, WorkspacePath]) -> WorkspacePath:
        if isinstance(p, WorkspacePath):
            return p

        return WorkspacePath(self, p)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self._base_dir}>"


if __name__ == "__main__":
    proj = Workspace("/loris_analyzer/_output/0/g973f/0x3c7b.d/0.0x42.d/4")
    proj.create()
    print(proj)
    m = proj.path("/mappings.py")
    print(m.exists())
    from loris_analyzer.util.utils import import_source_file

    mappings = import_source_file(m.to_path(), "mappings")
    print(mappings.__getattribute__("symbol_mappings"))
