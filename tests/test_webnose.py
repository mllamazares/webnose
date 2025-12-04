import pytest
import sys
import os
import json
from unittest.mock import MagicMock, patch

# Add parent directory to path to import webnose
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import webnose

@pytest.fixture
def mock_response():
    mock = MagicMock()
    mock.status_code = 200
    mock.text = "<html><body><input type='password'></body></html>"
    mock.headers = {'Server': 'nginx'}
    return mock

def test_fetch_url_success(mock_response):
    with patch('requests.get', return_value=mock_response) as mock_get:
        result = webnose.fetch_url("http://example.com")
        assert result['url'] == "http://example.com"
        assert result['error'] is None
        assert result['body'] == mock_response.text

def test_fetch_url_failure():
    with patch('requests.get', side_effect=Exception("Connection refused")) as mock_get:
        result = webnose.fetch_url("http://example.com")
        assert result['url'] == "http://example.com"
        assert result['error'] == "Connection refused"

def test_analyze_target_success(mock_response):
    templates = [{
        'id': 'test_smell',
        'info': {'risk_score': 5.0},
        'matchers': [{
            'type': 'regex',
            'part': 'body',
            'regex': ['password']
        }]
    }]
    
    with patch('requests.get', return_value=mock_response):
        result = webnose.analyze_target("http://example.com", templates, 10, False)
        assert result['smells']['test_smell'] == 1
        assert result['smell_count'] == 1
        assert result['risk_score'] == 5.0

def test_analyze_target_error():
    templates = []
    with patch('requests.get', side_effect=Exception("Fail")):
        result = webnose.analyze_target("http://example.com", templates, 10, False)
        assert result['error'] == "Fail"
        assert result['smell_count'] == 0
        assert result['risk_score'] == 0.0

def test_random_user_agent():
    with patch('webnose.UserAgent') as MockUA, \
         patch('requests.get') as mock_get:
        
        mock_ua_instance = MockUA.return_value
        mock_ua_instance.random = "TestAgent/1.0"
        
        result = webnose.fetch_url("http://example.com", random_agent=True)
        
        if mock_get.call_args is None:
            pytest.fail(f"requests.get was not called. Result: {result}")
            
        call_args = mock_get.call_args
        headers = call_args[1]['headers']
        assert headers['User-Agent'] == "TestAgent/1.0"

def test_integration_empty_output_debug(tmp_path):
    # Create a dummy input file
    input_file = tmp_path / "urls.txt"
    input_file.write_text("http://example.com")
    
    # Create a dummy template
    templates_dir = tmp_path / "smells"
    templates_dir.mkdir()
    (templates_dir / "test.yaml").write_text("id: test\ninfo:\n  risk_score: 1.0\nmatchers:\n  - type: regex\n    regex: ['.*']")
    
    # Run main logic (mocking requests to avoid network)
    with patch('requests.get') as mock_get:
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = "content"
        mock_get.return_value.headers = {}
        
        # We can't easily call main() because it parses args.
        # Let's call analyze_target directly and check result.
        templates = webnose.load_templates(str(templates_dir))
        result = webnose.analyze_target("http://example.com", templates, 10, False)
        
        assert result.get('error') is None
        assert result['smell_count'] > 0
        assert result['risk_score'] > 0

def test_case_sensitivity():
    # Case insensitive match (default)
    template_insensitive = {
        'id': 'insensitive',
        'matchers': [{
            'type': 'regex',
            'regex': ['PASSWORD'],
            'case_insensitive': True
        }]
    }
    content = {'body': 'password', 'url': '', 'headers': {}}
    assert webnose.count_smell_instances(content, template_insensitive) == 1

    # Case sensitive match (fail)
    template_sensitive = {
        'id': 'sensitive',
        'matchers': [{
            'type': 'regex',
            'regex': ['PASSWORD'],
            'case_insensitive': False
        }]
    }
    assert webnose.count_smell_instances(content, template_sensitive) == 0
    
    # Case sensitive match (pass)
    content_upper = {'body': 'PASSWORD', 'url': '', 'headers': {}}
    assert webnose.count_smell_instances(content_upper, template_sensitive) == 1

def test_instance_counting():
    # Positive counting
    template_count = {
        'id': 'count',
        'matchers': [{
            'type': 'regex',
            'regex': ['test'],
            'case_insensitive': True
        }]
    }
    content = {'body': 'test test Test', 'url': '', 'headers': {}}
    assert webnose.count_smell_instances(content, template_count) == 3
    
    # Negative counting
    template_negative = {
        'id': 'negative',
        'matchers': [{
            'type': 'regex',
            'regex': ['missing'],
            'negative': True
        }]
    }
    # Present (pattern missing) -> count 1
    assert webnose.count_smell_instances(content, template_negative) == 1
    
    # Absent (pattern present) -> count 0
    content_with_missing = {'body': 'missing', 'url': '', 'headers': {}}
    assert webnose.count_smell_instances(content_with_missing, template_negative) == 0

if __name__ == "__main__":
    # Manually run if executed directly
    pass
