from backend.routers.admin_tools import COMMANDS


def test_admin_toolbox_is_allowlisted_and_has_project_operations():
    assert "system.health" in COMMANDS
    assert "security.posture" in COMMANDS
    assert not any("shell" in key or "exec" in key for key in COMMANDS)