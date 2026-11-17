from unittest import mock

from malaz.analysis import privilege


def test_is_admin_returns_bool_or_none():
    result = privilege.is_admin()
    assert result in (True, False, None)


def test_label_normal_user():
    with mock.patch.object(privilege, "is_admin", return_value=False):
        assert "normaler Nutzer" in privilege.privilege_label()


def test_label_admin():
    with mock.patch.object(privilege, "is_admin", return_value=True):
        assert privilege.privilege_label() == "Administrator"


def test_label_unknown():
    with mock.patch.object(privilege, "is_admin", return_value=None):
        assert privilege.privilege_label() == "unbekannt"


def test_is_admin_handles_errors():
    # Force the platform branch to raise; must degrade to None, never crash.
    with mock.patch.object(privilege.sys, "platform", "win32"), mock.patch.object(
        privilege.ctypes, "windll", mock.Mock(shell32=mock.Mock(IsUserAnAdmin=mock.Mock(side_effect=OSError)))
    ):
        assert privilege.is_admin() is None
