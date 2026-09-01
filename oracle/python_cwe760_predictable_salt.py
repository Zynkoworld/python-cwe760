"""python-cwe760 -- predictable (literal) salt in a key-derivation call.

decide(code, line) -> "FLAG" | "SAFE".  FLAG iff the given line contains a recognized KDF call whose
salt argument is a LITERAL constant (bytes/str constant, a constant `.encode()`, or a concatenation of
constants). Anything non-literal (a name, a call such as os.urandom / secrets.token_bytes /
bcrypt.gensalt) yields SAFE -- the decider never guesses about values it cannot see.
stdlib `ast` only; no code is executed. Clean-room rule, no third-party analyzer installed or run.
"""
import ast

CWE = "CWE-760"

# hivas-nev -> (pozicionalis salt-index, kulcsszavas salt-nev)
_KDF = {
    "pbkdf2_hmac": (2, "salt"),
    "scrypt": (None, "salt"),
    "hashpw": (1, None),          # bcrypt.hashpw(pw, salt)
    "kdf": (None, "salt"),        # bcrypt.kdf(password=..., salt=...)
    "derive_key": (None, "salt"),
}


def _callee(node):
    f = node.func
    if isinstance(f, ast.Attribute):
        return f.attr
    if isinstance(f, ast.Name):
        return f.id
    return None


def _is_literal(node):
    """Literal konstans, konstans .encode(), vagy csak-konstansokbol allo osszefuzes."""
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
            and node.func.attr in ("encode", "decode") and _is_literal(node.func.value):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_literal(node.left) and _is_literal(node.right)
    if isinstance(node, ast.JoinedStr):
        return all(isinstance(v, ast.Constant) for v in node.values)
    return False


def decide(code, line):
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return "SAFE"
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or getattr(node, "lineno", None) != line:
            continue
        name = _callee(node)
        if name not in _KDF:
            continue
        pos, kw = _KDF[name]
        salt = None
        if kw is not None:
            for k in node.keywords:
                if k.arg == kw:
                    salt = k.value
        if salt is None and pos is not None and len(node.args) > pos:
            salt = node.args[pos]
        if salt is not None and _is_literal(salt):
            return "FLAG"
    return "SAFE"
