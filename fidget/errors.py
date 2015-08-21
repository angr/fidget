class FidgetError(Exception):
    pass

class FidgetUnsupportedError(FidgetError):
    pass

class ValueNotFoundError(FidgetError):
    pass

class FuzzingAssertionFailure(FidgetError):
    pass

class FidgetAnalysisFailure(FidgetError):
    pass
