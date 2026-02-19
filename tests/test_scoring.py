
import pytest
from tests.dfp import DFPManager, DevicePM, DeviceStatusEnum

def create_mock_device(device_id: int, email: str = "test@example.com") -> DevicePM:
    return DevicePM(
        id=device_id,
        ts_node_id=f"node_{device_id}",
        ts_name=f"device_{device_id}",
        ts_ip="100.64.0.1",
        device_model="Test Phone",
        email=email,
        browser="chrome",
        status=DeviceStatusEnum.ACTIVE
    )

@pytest.fixture
def manager():
    m = DFPManager(fp_js="console.log('test')")
    return m

def test_scoring_perfect_session(manager):
    """2 devices, 2 batches, unique and consistent IDs."""
    devices = [create_mock_device(1, "a@ex.com"), create_mock_device(2, "b@ex.com")]
    browsers = ["chrome", "brave"]
    
    # Gen structure (n_repeat=1 means 1 of each browser = 2 batches total)
    manager.gen_session_structure(devices, browsers, n_repeat=1)
    
    # Simulate consistent reporting
    # Structure is Dict[browser, List[dict]]
    for browser, batch in manager.session_structure.items():
        for item in batch:
            device_id = item["device_cfg"].id
            order_id = item["order_id"]
            manager.update_fingerprint(order_id, f"unique_id_for_device_{device_id}")
            
    score = manager.calculate_score()
    assert score == 1.0

def test_scoring_min_devices(manager):
    """Fails if fewer than 2 physical devices report."""
    devices = [create_mock_device(1), create_mock_device(2)]
    manager.gen_session_structure(devices, ["chrome"], n_repeat=1)
    
    # Only device 1 reports
    for item in manager.session_structure["chrome_1"]:
        if item["device_cfg"].id == 1:
            manager.update_fingerprint(item["order_id"], "id_1")
            
    score = manager.calculate_score()
    assert score == 0.0

def test_scoring_fragmentation_penalty(manager):
    """Device reports different IDs in different batches."""
    devices = [create_mock_device(1), create_mock_device(2)]
    manager.gen_session_structure(devices, ["chrome", "brave"], n_repeat=1)
    
    # Device 2 is consistent
    # Device 1 fragments: "id_1_a" in chrome, "id_1_b" in brave
    for item in manager.session_structure["chrome_1"]:
        manager.update_fingerprint(item["order_id"], f"id_{item['device_cfg'].id}_consistent")
        
    for item in manager.session_structure["brave_1"]:
        if item["device_cfg"].id == 1:
            manager.update_fingerprint(item["order_id"], "id_1_fragmented")
        else:
            manager.update_fingerprint(item["order_id"], "id_2_consistent")
            
    # Device 1: 1.0 - 0.3 = 0.7
    # Device 2: 1.0
    # Average: (0.7 + 1.0) / 2 = 0.85
    score = manager.calculate_score()
    assert score == 0.85

def test_scoring_max_fragmentation(manager):
    """Device hits max fragmentation limit."""
    devices = [create_mock_device(1), create_mock_device(2)]
    # Need 3 batches to get 3 unique IDs
    manager.gen_session_structure(devices, ["chrome", "brave", "safari"], n_repeat=1)
    
    for item in manager.session_structure["chrome_1"]:
        manager.update_fingerprint(item["order_id"], f"id_{item['device_cfg'].id}_1")
    for item in manager.session_structure["brave_1"]:
        manager.update_fingerprint(item["order_id"], f"id_{item['device_cfg'].id}_2")
    for item in manager.session_structure["safari_1"]:
        manager.update_fingerprint(item["order_id"], f"id_{item['device_cfg'].id}_3")
        
    # Both devices have 3 unique IDs. max_fragmentation is 3.
    # Rule: if unique_fps_count >= max_fragmentation: score = 0.0
    score = manager.calculate_score()
    assert score == 0.0

def test_scoring_soft_collision(manager):
    """Devices share an ID in 1 batch (Strike 1)."""
    devices = [create_mock_device(1), create_mock_device(2)]
    manager.gen_session_structure(devices, ["chrome"], n_repeat=1)
    
    # Batch 1: Collision
    for item in manager.session_structure["chrome_1"]:
        manager.update_fingerprint(item["order_id"], "shared_id")
        
    # Both devices: 1.0 - 0.25 (collision penalty) = 0.75
    score = manager.calculate_score()
    assert score == 0.75

def test_scoring_hard_collision(manager):
    """Devices share an ID in 2 batches (Strike 2)."""
    devices = [create_mock_device(1), create_mock_device(2)]
    manager.gen_session_structure(devices, ["chrome", "brave"], n_repeat=1)
    
    # All batches share same ID
    for browser_batch in manager.session_structure.values():
        for item in browser_batch:
            manager.update_fingerprint(item["order_id"], "shared_id")
            
    # Both devices failed uniqueness in 2 batches. Score = 0.0
    score = manager.calculate_score()
    assert score == 0.0

def test_scoring_mixed_penalties(manager):
    """One device has both collision and fragmentation."""
    devices = [create_mock_device(1), create_mock_device(2)]
    manager.gen_session_structure(devices, ["chrome", "brave"], n_repeat=1)
    
    # Device 2: Perfect
    # Device 1: 
    #   Batch 1 (chrome): "shared_id" (Collision with Device 2)
    #   Batch 2 (brave): "fragment_id" (Fragmentation)
    
    # chrome_1
    for item in manager.session_structure["chrome_1"]:
        manager.update_fingerprint(item["order_id"], "shared_id")
    
    # brave_1
    for item in manager.session_structure["brave_1"]:
        if item["device_cfg"].id == 1:
            manager.update_fingerprint(item["order_id"], "fragment_id")
        else:
            manager.update_fingerprint(item["order_id"], "device_2_unique")
            
    # Device 2: 
    #   unique_fps: {"shared_id", "device_2_unique"} -> unique_count=2 -> -0.3 penalty
    #   collision: "shared_id" in 1 batch -> -0.25 penalty
    #   Points: 1.0 - 0.3 - 0.25 = 0.45
    
    # Device 1:
    #   unique_fps: {"shared_id", "fragment_id"} -> unique_count=2 -> -0.3 penalty
    #   collision: "shared_id" in 1 batch -> -0.25 penalty
    #   Points: 1.0 - 0.3 - 0.25 = 0.45
    
    # Average: 0.45
    score = manager.calculate_score()
    assert score == 0.45
