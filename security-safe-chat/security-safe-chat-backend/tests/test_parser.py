"""
tests/test_parser.py — Unit tests for app.parser covering all 5 cases.

Run with:  pytest tests/ -v
"""

import pytest
from app.parser import parse


class TestCase1Single:
    def test_known_id_with_entities(self):
        result = parse("1.1.1|name=Rahul,money=10000000")
        assert result["case"] == 1
        assert result["is_scam"] is True
        assert result["matches"][0]["id"] == "1.1.1"
        assert result["entities"]["name"] == "Rahul"
        assert result["entities"]["money"] == "10000000"

    def test_known_id_no_entities(self):
        result = parse("2.1.3|")
        assert result["case"] == 1
        assert result["is_scam"] is True
        assert result["matches"][0]["id"] == "2.1.3"

    def test_unknown_id_still_case1(self):
        result = parse("99.99.99|name=Test")
        assert result["case"] == 1
        assert result["is_scam"] is True
        assert result["matches"][0]["id"] == "99.99.99"

    def test_detection_message_filled(self):
        result = parse("4.1.1|name=Priya,money=5000,authority=CBI")
        msg = result["matches"][0]["detection_message"]
        assert "Priya" in msg
        assert "5000" in msg
        assert "CBI" in msg

    def test_placeholders_filtered(self):
        # 2.1.3 only accepts [name], so money should be stripped
        result = parse("2.1.3|name=Anil,money=99999")
        entities = result["matches"][0]["entities"]
        assert "name" in entities
        assert "money" not in entities

    def test_score_present(self):
        result = parse("1.1.1|name=X,money=100")
        assert result["score"] == 100

    def test_multi_key_values(self):
        result = parse("7.2.1|name=Priya,item=iPhone 15,value=80000,money=4999")
        assert result["entities"]["item"] == "iPhone 15"
        assert result["entities"]["value"] == "80000"
        assert result["entities"]["money"] == "4999"


class TestCase2Multi:
    def test_multi_two_ids(self):
        result = parse("multi:1.1.1+4.1.1|name=Rahul,money=10000000,authority=Income Tax")
        assert result["case"] == 2
        assert result["is_scam"] is True
        assert len(result["matches"]) == 2
        ids = [m["id"] for m in result["matches"]]
        assert "1.1.1" in ids
        assert "4.1.1" in ids

    def test_multi_three_ids(self):
        result = parse("multi:1.1.1+4.1.1+2.1.1|name=Test,money=5000,authority=Police")
        assert len(result["matches"]) == 3

    def test_multi_score_is_highest(self):
        result = parse("multi:1.1.1+4.1.1|name=X,money=100,authority=CBI")
        assert result["score"] == 100


class TestCase3Generic:
    def test_gen_with_name_and_money(self):
        result = parse("gen|name=Rahul,money=5000")
        assert result["case"] == 3
        assert result["is_scam"] is True
        assert result["generic_scam"] is True
        assert result["entities"]["name"] == "Rahul"
        assert result["entities"]["money"] == "5000"

    def test_gen_name_only(self):
        result = parse("gen|name=Sara")
        assert result["case"] == 3
        assert result["entities"].get("name") == "Sara"

    def test_gen_has_detection_message(self):
        result = parse("gen|name=X")
        assert isinstance(result.get("detection_message"), str)
        assert len(result["detection_message"]) > 10


class TestCase4Unsure:
    def test_unsure(self):
        result = parse("unsure")
        assert result["case"] == 4
        assert result["is_scam"] is False
        assert result["ambiguous"] is True
        assert result["matches"] == []


class TestCase5Safe:
    def test_err(self):
        result = parse("err")
        assert result["case"] == 5
        assert result["is_scam"] is False
        assert result["matches"] == []


class TestFallback:
    def test_garbage_input_returns_case4(self):
        result = parse("this is garbage output!!!")
        assert result["case"] == 4
        assert "parse_error" in result

    def test_empty_string_returns_case4(self):
        result = parse("")
        assert result["case"] == 4

    def test_whitespace_normalized(self):
        result = parse("  err  ")
        assert result["case"] == 5
