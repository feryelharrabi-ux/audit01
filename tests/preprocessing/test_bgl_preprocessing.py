from src.preprocessing.data_preprocessing_bgl import event_id_from_template, normalize_template


def test_template_normalization_replaces_variable_values():
    template = normalize_template("ERROR node 10.0.0.1 failed request 123")
    assert "<IP>" in template
    assert "<NUM>" in template


def test_event_id_is_stable_for_same_template():
    template = "ERROR request <NUM> failed"
    assert event_id_from_template(template) == event_id_from_template(template)