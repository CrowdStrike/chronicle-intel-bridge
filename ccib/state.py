import json
import os
import tempfile
from .config import config
from .log import log


def _state_file_path():
    return config.get('state', 'file')


def load_state():
    """Load persisted state from the state file.

    Returns the state dict if successful, or None if the file is
    missing, empty, or corrupt (with a warning logged).
    """
    path = _state_file_path()
    if not os.path.exists(path):
        log.info("No state file found at %s, starting fresh", path)
        return None

    try:
        with open(path, 'r', encoding='utf-8') as fh:
            state = json.load(fh)
        log.info("Loaded state from %s: %s", path, state)
        return state
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("Could not read state file %s (%s), starting fresh", path, exc)
        return None


def save_state(state):
    """Atomically persist state to the state file.

    Writes to a temporary file in the same directory, then renames
    to avoid corruption if the process is killed mid-write.
    """
    path = _state_file_path()
    dir_name = os.path.dirname(path) or '.'

    os.makedirs(dir_name, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            json.dump(state, fh)
        os.replace(tmp_path, path)
        log.debug("State saved to %s", path)
    except Exception:
        # Clean up the temp file on failure
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
