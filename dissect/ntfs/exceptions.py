class Error(Exception):
    pass


class BrokenIndexError(Error):
    pass


class BrokenMftError(Error):
    pass


class FilenameNotAvailableError(Error):
    pass


class FileNotFoundError(Error):
    pass


class MftNotAvailableError(Error):
    pass


class NotADirectoryError(Error):
    pass


class VolumeNotAvailableError(Error):
    pass
