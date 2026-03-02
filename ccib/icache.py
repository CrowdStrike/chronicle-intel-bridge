import hashlib
import json
from collections import OrderedDict

from .log import log


class ICache:
    """Cache for indicators."""
    def __init__(self, max_size=None):
        self.cache = OrderedDict()
        self.max_size = max_size
        self.evictions = 0
        log.debug("Initialized indicator cache (max_size=%s)", max_size)

    def exists(self, indicator):
        """Check if an indicator exists in the cache."""
        cpy = indicator.copy()
        cpy.pop('last_updated')

        for label in cpy.get('labels', []):
            label.pop('created_on')
        for rel in cpy.get('relations', []):
            rel.pop('created_date')

        iid = cpy.pop('id')

        content_hash = hashlib.sha256(
            json.dumps(cpy, sort_keys=True, default=str).encode()
        ).hexdigest()

        if iid in self.cache:
            if self.cache[iid] == content_hash:
                self.cache.move_to_end(iid)
                return True
            # Content changed — update hash
            self.cache[iid] = content_hash
            self.cache.move_to_end(iid)
            return False

        self.cache[iid] = content_hash
        self._evict_if_needed()
        return False

    def _evict_if_needed(self):
        """Evict oldest entries if cache exceeds max_size."""
        if self.max_size is None:
            return
        while len(self.cache) > self.max_size:
            self.cache.popitem(last=False)
            self.evictions += 1

    def get_stats(self):
        """Return cache statistics."""
        return {'size': len(self.cache), 'max_size': self.max_size, 'evictions': self.evictions}


from .config import config  # noqa: E402  pylint: disable=C0413
_max_size_val = int(config.get('icache', 'max_size'))
icache = ICache(max_size=_max_size_val if _max_size_val > 0 else None)
