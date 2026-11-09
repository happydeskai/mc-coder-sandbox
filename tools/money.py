"""Money formatting helpers. Amounts are integer pence; never floats."""


def format_pence(pence):
    """Format integer pence as pounds: 1234 -> "£12.34", 0 -> "£0.00", -1234 -> "-£12.34".

    No thousands separator. Raises TypeError for anything that is not an int (floats and bools included).
    """
    if not isinstance(pence, int) or isinstance(pence, bool):
        raise TypeError(f"pence must be an int, got {type(pence).__name__}")
    sign = "-" if pence < 0 else ""
    pounds, rest = divmod(abs(pence), 100)
    return f"{sign}£{pounds}.{rest:02d}"
