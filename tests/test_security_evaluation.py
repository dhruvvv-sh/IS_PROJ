import json

from cipherchat.security.evaluation import main, run_evaluation, write_json, write_jsonl, write_markdown


def test_preliminary_security_evaluation_documents_every_required_property():
    report = run_evaluation(sample_size=12)
    by_property = {result.security_property: result for result in report.results}

    assert set(by_property) == {
        "Confidentiality", "Authenticity", "Integrity", "Non-repudiation",
        "Evidence tampering", "Access control",
    }
    assert by_property["Confidentiality"].metrics["wrong_key_rejection_rate"] == 1.0
    assert by_property["Authenticity"].metrics["forgery_rejection_rate"] == 1.0
    assert by_property["Integrity"].metrics["tamper_detection_rate"] == 1.0
    assert by_property["Evidence tampering"].metrics["tampering_detection_rate"] == 1.0
    assert by_property["Access control"].metrics["unauthorized_rejection_rate"] == 1.0

    assert by_property["Non-repudiation"].status == "PASS"
    assert by_property["Non-repudiation"].metrics["peer_forgery_accepted"] is False
    assert by_property["Non-repudiation"].metrics["digital_signatures_present"] is True
    assert report.overall_status == "PASS"


def test_evaluation_writes_interpretable_markdown_and_one_json_log_per_case(tmp_path):
    report = run_evaluation(sample_size=3)
    jsonl = tmp_path / "security_evaluation.jsonl"
    json_path = tmp_path / "security_evaluation.json"
    markdown = tmp_path / "SECURITY_TEST_REPORT.md"

    write_jsonl(report, jsonl)
    write_json(report, json_path)
    write_markdown(report, markdown, jsonl.name, json_name=json_path.name)

    records = [json.loads(line) for line in jsonl.read_text().splitlines()]
    assert len(records) == len(report.results) == 6
    assert all({"case_id", "status", "metrics", "interpretation"} <= record.keys() for record in records)
    assert all("plaintext" not in record and "session_key" not in record for record in records)

    full_log = json.loads(json_path.read_text(encoding="utf-8"))
    assert full_log["report_format"] == "cipherchat-security-evaluation-v1"
    assert full_log["overall_status"] == "PASS"
    assert "system_limits" in full_log
    assert full_log["system_limits"]["max_plaintext_size"] > 0
    assert len(full_log["results"]) == 6
    assert all("plaintext" not in r and "session_key" not in r for r in full_log["results"])

    text = markdown.read_text()
    assert "Overall status: **PASS**" in text
    assert "Non-repudiation" in text
    assert "Ed25519 signatures prevent" in text


def test_single_cli_command_prints_a_self_contained_evaluator_report(tmp_path, capsys):
    exit_code = main(["--sample-size", "3", "--output-dir", str(tmp_path)])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "CIPHERCHAT PRELIMINARY INFORMATION-SECURITY EVALUATION" in output
    assert "WHAT IS TESTED" in output
    assert "EXPECTED" in output
    assert "OBSERVED" in output
    assert "METRICS" in output
    assert "MEANING" in output
    assert "FINAL SECURITY POSTURE" in output
    assert "OVERALL STATUS : PASS" in output
    assert "JSON AUDIT LOG" in output
    assert "JSONL AUDIT LOG" in output
    assert (tmp_path / "security_evaluation.json").exists()
    assert (tmp_path / "security_evaluation.jsonl").exists()
    assert (tmp_path / "SECURITY_TEST_REPORT.md").exists()
