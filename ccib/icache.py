import time


class ICache:
    """Cache for indicators."""
    def __init__(self):
        self.cache = {}

    def purge_before(self, timestamp):
        """Remove cache entries older than timestamp."""
        to_remove = [iid for iid, (_, ts) in self.cache.items() if ts < timestamp]
        for iid in to_remove:
            del self.cache[iid]

    def exists(self, indicator):
        """Check if an indicator exists in the cache."""
        cpy = indicator.copy()
        cpy.pop('last_updated')

        for label in cpy.get('labels', []):
            label.pop('created_on')
        for rel in cpy.get('relations', []):
            rel.pop('created_date')

        iid = cpy.pop('id')

        matches = self._matches(iid, cpy)
        self.cache[iid] = (cpy, time.time())
        return matches

    def _matches(self, iid, indicator):
        """Check if an indicator matches the cache entry."""
        if iid not in self.cache:
            return False

        cached_indicator, _ = self.cache[iid]

        if cached_indicator == indicator:
            return True

        return self.__class__.indicators_equal(cached_indicator, indicator)

    @classmethod
    def indicators_equal(cls, one, other):
        """Compare two indicator dictionaries for equality."""
        for k, v in one.items():
            if v != other[k]:
                if v is None or other[k] is None:
                    return False

                if isinstance(v, list) and isinstance(other[k], list):
                    if len(v) != len(other[k]):
                        return False
                if k == 'labels':
                    if set(label['name'] for label in v) != set(label['name'] for label in other[k]):
                        return False
                elif k == 'relations':
                    if set(rel['id'] for rel in v) != set(rel['id'] for rel in other[k]):
                        return False
                else:
                    return False
        return True


icache = ICache()
