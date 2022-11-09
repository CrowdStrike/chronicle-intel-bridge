class ICache:
    def __init__(self):
        self.cache = {}

    def exists(self, indicator):
        cpy = indicator.copy()
        cpy.pop('last_updated')

        for label in cpy.get('labels', []):
            label.pop('created_on')
        for rel in cpy.get('relations', []):
            rel.pop('created_date')

        iid = cpy.pop('id')

        matches = self._matches(iid, cpy)
        self.cache[iid] = cpy
        return matches

    def _matches(self, iid, indicator):
        if iid not in self.cache:
            return False

        if self.cache[iid] == indicator:
            return True

        cpy = indicator
        for k, v in self.cache[iid].items():
            if v != cpy[k]:
                if v is None or cpy[k] is None:
                    return False

                if isinstance(v, list) and isinstance(cpy[k], list):
                    if len(v) != len(cpy[k]):
                        return False
                if k == 'labels':
                    # sorting of the labels sometimes mismatches
                    aset = set(l['name'] for l in v)
                    bset = set(l['name'] for l in cpy[k])

                    if aset != bset:
                        return False
                elif k == 'relations':
                    aset = set(l['id'] for l in v)
                    bset = set(l['id'] for l in cpy[k])
                    if aset != bset:
                        return False
                else:
                    print("{}:".format(k))
                    print("    '{}'".format(v))
                    print("    '{}'".format(cpy[k]))
                    breakpoint()
        return True


icache = ICache()
