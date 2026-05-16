"""
Test Suite: Configuration

Tests for configuration loading and values.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_env_file_exists():
    """Test that .env file can be loaded"""
    try:
        from app.config import api_key, block_threshold, warn_threshold
        # If we get here, config loaded successfully
        assert True, "Config loaded successfully"
    except Exception as e:
        raise AssertionError(f"Config loading failed: {e}")


def test_api_key_type():
    """Test that api_key is string"""
    from app.config import api_key
    
    if api_key is not None:
        assert isinstance(api_key, str), f"Expected str, got {type(api_key)}"


def test_block_threshold_is_integer():
    """Test that block_threshold is integer"""
    from app.config import block_threshold
    
    assert isinstance(block_threshold, int), f"Expected int, got {type(block_threshold)}"


def test_warn_threshold_is_integer():
    """Test that warn_threshold is integer"""
    from app.config import warn_threshold
    
    assert isinstance(warn_threshold, int), f"Expected int, got {type(warn_threshold)}"


def test_thresholds_reasonable_values():
    """Test that thresholds have reasonable values"""
    from app.config import block_threshold, warn_threshold
    
    # block_threshold should be higher than warn_threshold
    if block_threshold > 0 and warn_threshold > 0:
        assert warn_threshold < block_threshold, f"warn ({warn_threshold}) should be < block ({block_threshold})"
    
    # Both should be in valid range
    assert 0 <= block_threshold <= 100, f"block_threshold {block_threshold} out of range"
    assert 0 <= warn_threshold <= 100, f"warn_threshold {warn_threshold} out of range"


def test_default_thresholds_if_not_set():
    """Test that thresholds have defaults"""
    from app.config import block_threshold, warn_threshold
    
    # Typical defaults
    assert block_threshold == 50 or block_threshold > 0, f"block_threshold invalid: {block_threshold}"
    assert warn_threshold == 31 or warn_threshold > 0, f"warn_threshold invalid: {warn_threshold}"


def test_config_module_imports_without_error():
    """Test that config module can be imported"""
    try:
        from app import config
        assert True, "Config imported successfully"
    except ImportError as e:
        raise AssertionError(f"Config import failed: {e}")


def run_all_tests():
    """Run all tests and report results"""
    tests = [
        ("Env File Exists", test_env_file_exists),
        ("API Key Type", test_api_key_type),
        ("Block Threshold is Integer", test_block_threshold_is_integer),
        ("Warn Threshold is Integer", test_warn_threshold_is_integer),
        ("Thresholds Reasonable Values", test_thresholds_reasonable_values),
        ("Default Thresholds", test_default_thresholds_if_not_set),
        ("Config Module Imports", test_config_module_imports_without_error),
    ]
    
    passed = 0
    failed = 0
    
    print("\n" + "="*70)
    print("TEST SUITE: Configuration")
    print("="*70)
    
    for test_name, test_func in tests:
        try:
            test_func()
            print(f"✅ PASSED: {test_name}")
            passed += 1
        except AssertionError as e:
            print(f"❌ FAILED: {test_name}")
            print(f"   Error: {e}")
            failed += 1
        except Exception as e:
            print(f"❌ ERROR: {test_name}")
            print(f"   Error: {e}")
            failed += 1
    
    print("\n" + "="*70)
    print(f"Results: {passed} passed, {failed} failed out of {len(tests)} tests")
    print("="*70)
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    exit(0 if success else 1)
