from ccib.threads import transform


def test_transform_removes_marker():
    indicator = {
        '_marker': 'abc123',
        'id': 'ind-1',
        'indicator': '1.2.3.4',
        'labels': [],
        'relations': [],
    }
    result = transform(indicator)
    assert '_marker' not in result


def test_transform_strips_label_last_valid_on():
    indicator = {
        '_marker': 'abc123',
        'id': 'ind-1',
        'indicator': '1.2.3.4',
        'labels': [{'name': 'malware', 'last_valid_on': 1700000000}],
        'relations': [],
    }
    result = transform(indicator)
    assert 'last_valid_on' not in result['labels'][0]


def test_transform_strips_relation_last_valid_date():
    indicator = {
        '_marker': 'abc123',
        'id': 'ind-1',
        'indicator': '1.2.3.4',
        'labels': [],
        'relations': [{'id': 'rel-1', 'type': 'parent', 'last_valid_date': 1700000000}],
    }
    result = transform(indicator)
    assert 'last_valid_date' not in result['relations'][0]
