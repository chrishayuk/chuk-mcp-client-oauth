"""Tests for CLI module."""

from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest

from chuk_mcp_client_oauth.cli import (
    cmd_auth,
    cmd_clear,
    cmd_get,
    cmd_list,
    cmd_logout,
    cmd_test,
    main,
    print_header,
    safe_display_token,
)
from chuk_mcp_client_oauth.oauth_config import OAuthTokens


class TestSafeDisplayToken:
    """Test token display redaction."""

    def test_short_token(self):
        """Test redaction of short tokens."""
        token = "short123"
        result = safe_display_token(token)
        assert result == "short123..."
        assert "..." in result

    def test_normal_token(self):
        """Test redaction of normal length tokens."""
        token = "a" * 50
        result = safe_display_token(token)
        assert result.startswith("a" * 20)
        assert result.endswith("a" * 6)
        assert "..." in result
        assert "*" in result

    def test_long_token(self):
        """Test redaction of long tokens."""
        token = "x" * 100
        result = safe_display_token(token, prefix_len=10, suffix_len=4)
        assert result.startswith("x" * 10)
        assert result.endswith("x" * 4)
        assert "..." in result
        assert "*" in result


class TestPrintHeader:
    """Test header printing."""

    def test_print_header(self, capsys):
        """Test header is formatted correctly."""
        print_header("Test Header")
        captured = capsys.readouterr()
        assert "Test Header" in captured.out
        assert "=" * 60 in captured.out


class TestCmdAuth:
    """Test auth command."""

    @pytest.mark.asyncio
    async def test_auth_success(self):
        """Test successful authentication."""
        with patch("chuk_mcp_client_oauth.cli.OAuthHandler") as mock_handler_class:
            mock_handler = AsyncMock()
            mock_handler_class.return_value = mock_handler

            # Mock tokens
            mock_tokens = OAuthTokens(
                access_token="test_access_token_123",
                token_type="Bearer",
                expires_in=3600,
                refresh_token="test_refresh_token_456",
                scope="read write",
            )
            mock_handler.ensure_authenticated_mcp = AsyncMock(return_value=mock_tokens)

            # Mock token manager
            mock_handler.token_manager = Mock()
            mock_handler.token_manager.token_store = Mock()
            mock_handler.token_manager.token_store.__class__.__name__ = (
                "KeychainTokenStore"
            )

            result = await cmd_auth("test-server", "https://test.com/mcp", ["read"])

            assert result == 0
            mock_handler.ensure_authenticated_mcp.assert_called_once_with(
                server_name="test-server",
                server_url="https://test.com/mcp",
                scopes=["read"],
            )

    @pytest.mark.asyncio
    async def test_auth_with_default_scopes(self):
        """Test authentication with default scopes."""
        with patch("chuk_mcp_client_oauth.cli.OAuthHandler") as mock_handler_class:
            mock_handler = AsyncMock()
            mock_handler_class.return_value = mock_handler

            mock_tokens = OAuthTokens(
                access_token="test_token",
                token_type="Bearer",
                expires_in=3600,
            )
            mock_handler.ensure_authenticated_mcp = AsyncMock(return_value=mock_tokens)
            mock_handler.token_manager = Mock()
            mock_handler.token_manager.token_store = Mock()
            mock_handler.token_manager.token_store.__class__.__name__ = (
                "KeychainTokenStore"
            )

            result = await cmd_auth("test-server", "https://test.com/mcp", None)

            assert result == 0
            # Should use default scopes
            call_args = mock_handler.ensure_authenticated_mcp.call_args
            assert call_args[1]["scopes"] == ["read", "write"]

    @pytest.mark.asyncio
    async def test_auth_failure(self):
        """Test authentication failure."""
        with patch("chuk_mcp_client_oauth.cli.OAuthHandler") as mock_handler_class:
            mock_handler = AsyncMock()
            mock_handler_class.return_value = mock_handler
            mock_handler.ensure_authenticated_mcp = AsyncMock(
                side_effect=Exception("Auth failed")
            )

            result = await cmd_auth("test-server", "https://test.com/mcp")

            assert result == 1


class TestCmdGet:
    """Test get command."""

    def test_get_success(self):
        """Test successful token retrieval."""
        with patch("chuk_mcp_client_oauth.cli.TokenManager") as mock_manager_class:
            mock_manager = Mock()
            mock_manager_class.return_value = mock_manager

            # Mock tokens - use real OAuthTokens object
            mock_tokens = OAuthTokens(
                access_token="test_access_token",
                token_type="Bearer",
                expires_in=3600,
                refresh_token="test_refresh",
                scope="read write",
            )

            mock_manager.has_valid_tokens = Mock(return_value=True)
            mock_manager.load_tokens = Mock(return_value=mock_tokens)
            mock_manager.token_store = Mock()
            mock_manager.token_store.__class__.__name__ = "KeychainTokenStore"

            result = cmd_get("test-server")

            assert result == 0
            mock_manager.has_valid_tokens.assert_called_once_with("test-server")
            mock_manager.load_tokens.assert_called_once_with("test-server")

    def test_get_no_tokens(self):
        """Test get with no tokens found."""
        with patch("chuk_mcp_client_oauth.cli.TokenManager") as mock_manager_class:
            mock_manager = Mock()
            mock_manager_class.return_value = mock_manager
            mock_manager.has_valid_tokens = Mock(return_value=False)

            result = cmd_get("test-server")

            assert result == 1

    def test_get_load_failure(self):
        """Test get when token loading fails."""
        with patch("chuk_mcp_client_oauth.cli.TokenManager") as mock_manager_class:
            mock_manager = Mock()
            mock_manager_class.return_value = mock_manager
            mock_manager.has_valid_tokens = Mock(return_value=True)
            mock_manager.load_tokens = Mock(return_value=None)

            result = cmd_get("test-server")

            assert result == 1

    def test_get_expired_token(self):
        """Test get with expired token."""
        import time

        with patch("chuk_mcp_client_oauth.cli.TokenManager") as mock_manager_class:
            mock_manager = Mock()
            mock_manager_class.return_value = mock_manager

            # Create an expired token by setting issued_at to past
            mock_tokens = OAuthTokens(
                access_token="test_token",
                token_type="Bearer",
                expires_in=1,  # 1 second expiry
                issued_at=time.time() - 10,  # Issued 10 seconds ago
            )

            mock_manager.has_valid_tokens = Mock(return_value=True)
            mock_manager.load_tokens = Mock(return_value=mock_tokens)
            mock_manager.token_store = Mock()
            mock_manager.token_store.__class__.__name__ = "KeychainTokenStore"

            result = cmd_get("test-server")

            assert result == 0  # Still returns 0, just shows expired status


class TestCmdList:
    """Test list command."""

    def test_list_with_tokens(self):
        """Test listing tokens when they exist."""

        with patch("chuk_mcp_client_oauth.cli.TokenManager") as mock_manager_class:
            mock_manager = Mock()
            mock_manager_class.return_value = mock_manager

            # Mock token store with token_dir
            mock_token_dir = Mock()
            mock_token_dir.exists = Mock(return_value=True)

            # Create Path-like objects that can be sorted
            # Use actual Path objects for testing
            mock_file1 = Path("/tmp/server1.enc")
            mock_file2 = Path("/tmp/server2.enc")

            # Need to return an iterable that supports sorted()
            mock_token_dir.glob = Mock(return_value=[mock_file1, mock_file2])
            mock_manager.token_store = Mock()
            mock_manager.token_store.token_dir = mock_token_dir
            mock_manager.token_store.__class__.__name__ = "EncryptedFileTokenStore"

            # Mock tokens
            mock_tokens = OAuthTokens(
                access_token="test_token",
                token_type="Bearer",
                expires_in=3600,
            )

            mock_manager.has_valid_tokens = Mock(return_value=True)
            mock_manager.load_tokens = Mock(return_value=mock_tokens)

            result = cmd_list()

            assert result == 0

    def test_list_no_tokens(self):
        """Test listing when no tokens exist."""
        with patch("chuk_mcp_client_oauth.cli.TokenManager") as mock_manager_class:
            mock_manager = Mock()
            mock_manager_class.return_value = mock_manager

            mock_token_dir = Mock()
            mock_token_dir.exists = Mock(return_value=True)
            mock_token_dir.glob = Mock(return_value=[])  # No token files

            mock_manager.token_store = Mock()
            mock_manager.token_store.token_dir = mock_token_dir

            result = cmd_list()

            assert result == 0

    def test_list_no_token_dir(self):
        """Test listing when token directory doesn't exist."""
        with patch("chuk_mcp_client_oauth.cli.TokenManager") as mock_manager_class:
            mock_manager = Mock()
            mock_manager_class.return_value = mock_manager

            mock_token_dir = Mock()
            mock_token_dir.exists = Mock(return_value=False)

            mock_manager.token_store = Mock()
            mock_manager.token_store.token_dir = mock_token_dir

            result = cmd_list()

            assert result == 0

    def test_list_keychain_backend(self):
        """Test listing with keychain backend (no token_dir)."""
        with patch("chuk_mcp_client_oauth.cli.TokenManager") as mock_manager_class:
            mock_manager = Mock()
            mock_manager_class.return_value = mock_manager

            # Keychain backend doesn't have token_dir attribute
            mock_manager.token_store = Mock(spec=[])
            mock_manager.token_store.__class__.__name__ = "KeychainTokenStore"

            result = cmd_list()

            assert result == 0

    def test_list_error(self):
        """Test list command error handling."""
        with patch("chuk_mcp_client_oauth.cli.TokenManager") as mock_manager_class:
            mock_manager = Mock()
            mock_manager_class.return_value = mock_manager
            mock_manager.token_store = Mock()
            mock_manager.token_store.token_dir = Mock(
                side_effect=Exception("Storage error")
            )

            result = cmd_list()

            assert result == 1


class TestCmdClear:
    """Test clear command."""

    def test_clear_success(self):
        """Test successful token clearing."""
        with patch("chuk_mcp_client_oauth.cli.OAuthHandler") as mock_handler_class:
            mock_handler = Mock()
            mock_handler_class.return_value = mock_handler
            mock_handler.token_manager = Mock()
            mock_handler.token_manager.has_valid_tokens = Mock(return_value=True)
            mock_handler.clear_tokens = Mock()

            result = cmd_clear("test-server")

            assert result == 0
            mock_handler.clear_tokens.assert_called_once_with("test-server")

    def test_clear_no_tokens(self):
        """Test clearing when no tokens exist."""
        with patch("chuk_mcp_client_oauth.cli.OAuthHandler") as mock_handler_class:
            mock_handler = Mock()
            mock_handler_class.return_value = mock_handler
            mock_handler.token_manager = Mock()
            mock_handler.token_manager.has_valid_tokens = Mock(return_value=False)

            result = cmd_clear("test-server")

            assert result == 0

    def test_clear_error(self):
        """Test clear command error handling."""
        with patch("chuk_mcp_client_oauth.cli.OAuthHandler") as mock_handler_class:
            mock_handler = Mock()
            mock_handler_class.return_value = mock_handler
            mock_handler.token_manager = Mock()
            mock_handler.token_manager.has_valid_tokens = Mock(return_value=True)
            mock_handler.clear_tokens = Mock(side_effect=Exception("Clear failed"))

            result = cmd_clear("test-server")

            assert result == 1


class TestCmdLogout:
    """Test logout command."""

    @pytest.mark.asyncio
    async def test_logout_with_url(self):
        """Test logout with server URL."""
        with patch("chuk_mcp_client_oauth.cli.OAuthHandler") as mock_handler_class:
            mock_handler = AsyncMock()
            mock_handler_class.return_value = mock_handler

            mock_tokens = OAuthTokens(
                access_token="test_token",
                token_type="Bearer",
                expires_in=3600,
            )
            mock_handler.token_manager = Mock()
            mock_handler.token_manager.load_tokens = Mock(return_value=mock_tokens)
            mock_handler.logout = AsyncMock()

            result = await cmd_logout("test-server", "https://test.com/mcp")

            assert result == 0
            mock_handler.logout.assert_called_once_with(
                "test-server", "https://test.com/mcp"
            )

    @pytest.mark.asyncio
    async def test_logout_without_url(self):
        """Test logout without server URL."""
        with patch("chuk_mcp_client_oauth.cli.OAuthHandler") as mock_handler_class:
            mock_handler = AsyncMock()
            mock_handler_class.return_value = mock_handler

            mock_tokens = OAuthTokens(
                access_token="test_token",
                token_type="Bearer",
                expires_in=3600,
            )
            mock_handler.token_manager = Mock()
            mock_handler.token_manager.load_tokens = Mock(return_value=mock_tokens)
            mock_handler.logout = AsyncMock()

            result = await cmd_logout("test-server", None)

            assert result == 0
            mock_handler.logout.assert_called_once_with("test-server")

    @pytest.mark.asyncio
    async def test_logout_no_tokens(self):
        """Test logout when no tokens exist."""
        with patch("chuk_mcp_client_oauth.cli.OAuthHandler") as mock_handler_class:
            mock_handler = AsyncMock()
            mock_handler_class.return_value = mock_handler
            mock_handler.token_manager = Mock()
            mock_handler.token_manager.load_tokens = Mock(return_value=None)

            result = await cmd_logout("test-server")

            assert result == 0

    @pytest.mark.asyncio
    async def test_logout_error(self):
        """Test logout error handling."""
        with patch("chuk_mcp_client_oauth.cli.OAuthHandler") as mock_handler_class:
            mock_handler = AsyncMock()
            mock_handler_class.return_value = mock_handler

            mock_tokens = OAuthTokens(
                access_token="test_token",
                token_type="Bearer",
                expires_in=3600,
            )
            mock_handler.token_manager = Mock()
            mock_handler.token_manager.load_tokens = Mock(return_value=mock_tokens)
            mock_handler.logout = AsyncMock(side_effect=Exception("Logout failed"))

            result = await cmd_logout("test-server", "https://test.com/mcp")

            assert result == 1


class TestCmdTest:
    """Test test command."""

    @pytest.mark.asyncio
    async def test_test_success(self):
        """Test successful connection test."""
        with patch("chuk_mcp_client_oauth.cli.OAuthHandler") as mock_handler_class:
            mock_handler = AsyncMock()
            mock_handler_class.return_value = mock_handler

            mock_tokens = OAuthTokens(
                access_token="test_token",
                token_type="Bearer",
                expires_in=3600,
            )

            mock_handler.token_manager = Mock()
            mock_handler.token_manager.has_valid_tokens = Mock(return_value=True)
            mock_handler.token_manager.load_tokens = Mock(return_value=mock_tokens)

            result = await cmd_test("test-server")

            assert result == 0

    @pytest.mark.asyncio
    async def test_test_no_tokens(self):
        """Test connection test with no tokens."""
        with patch("chuk_mcp_client_oauth.cli.OAuthHandler") as mock_handler_class:
            mock_handler = AsyncMock()
            mock_handler_class.return_value = mock_handler
            mock_handler.token_manager = Mock()
            mock_handler.token_manager.has_valid_tokens = Mock(return_value=False)

            result = await cmd_test("test-server")

            assert result == 1

    @pytest.mark.asyncio
    async def test_test_load_failure(self):
        """Test connection test when loading fails."""
        with patch("chuk_mcp_client_oauth.cli.OAuthHandler") as mock_handler_class:
            mock_handler = AsyncMock()
            mock_handler_class.return_value = mock_handler
            mock_handler.token_manager = Mock()
            mock_handler.token_manager.has_valid_tokens = Mock(return_value=True)
            mock_handler.token_manager.load_tokens = Mock(return_value=None)

            result = await cmd_test("test-server")

            assert result == 1

    @pytest.mark.asyncio
    async def test_test_expired_token(self):
        """Test connection test with expired token."""
        import time

        with patch("chuk_mcp_client_oauth.cli.OAuthHandler") as mock_handler_class:
            mock_handler = AsyncMock()
            mock_handler_class.return_value = mock_handler

            # Create an expired token
            mock_tokens = OAuthTokens(
                access_token="test_token",
                token_type="Bearer",
                expires_in=1,
                issued_at=time.time() - 10,  # Expired
            )

            mock_handler.token_manager = Mock()
            mock_handler.token_manager.has_valid_tokens = Mock(return_value=True)
            mock_handler.token_manager.load_tokens = Mock(return_value=mock_tokens)

            result = await cmd_test("test-server")

            assert result == 1


class TestMain:
    """Test main CLI entry point."""

    def test_main_no_command(self):
        """Test main with no command."""
        with patch("sys.argv", ["cli.py"]):
            result = main()
            assert result == 1

    def test_main_help(self, capsys):
        """Test main with --help."""
        with patch("sys.argv", ["cli.py", "--help"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

    def test_main_auth_command(self):
        """Test main with auth command."""
        with patch("sys.argv", ["cli.py", "auth", "test-server", "https://test.com"]):
            with patch(
                "chuk_mcp_client_oauth.cli.cmd_auth", new_callable=AsyncMock
            ) as mock_auth:
                mock_auth.return_value = 0
                with patch("chuk_mcp_client_oauth.cli.asyncio.run") as mock_run:
                    mock_run.return_value = 0
                    result = main()
                    assert result == 0
                    mock_run.assert_called_once()

    def test_main_get_command(self):
        """Test main with get command."""
        with patch("sys.argv", ["cli.py", "get", "test-server"]):
            with patch("chuk_mcp_client_oauth.cli.cmd_get") as mock_get:
                mock_get.return_value = 0
                result = main()
                assert result == 0
                mock_get.assert_called_once_with("test-server")

    def test_main_list_command(self):
        """Test main with list command."""
        with patch("sys.argv", ["cli.py", "list"]):
            with patch("chuk_mcp_client_oauth.cli.cmd_list") as mock_list:
                mock_list.return_value = 0
                result = main()
                assert result == 0
                mock_list.assert_called_once()

    def test_main_clear_command(self):
        """Test main with clear command."""
        with patch("sys.argv", ["cli.py", "clear", "test-server"]):
            with patch("chuk_mcp_client_oauth.cli.cmd_clear") as mock_clear:
                mock_clear.return_value = 0
                result = main()
                assert result == 0
                mock_clear.assert_called_once_with("test-server")

    def test_main_logout_command(self):
        """Test main with logout command."""
        with patch(
            "sys.argv", ["cli.py", "logout", "test-server", "--url", "https://test.com"]
        ):
            with patch(
                "chuk_mcp_client_oauth.cli.cmd_logout", new_callable=AsyncMock
            ) as mock_logout:
                mock_logout.return_value = 0
                with patch("chuk_mcp_client_oauth.cli.asyncio.run") as mock_run:
                    mock_run.return_value = 0
                    result = main()
                    assert result == 0

    def test_main_test_command(self):
        """Test main with test command."""
        with patch("sys.argv", ["cli.py", "test", "test-server"]):
            with patch(
                "chuk_mcp_client_oauth.cli.cmd_test", new_callable=AsyncMock
            ) as mock_test:
                mock_test.return_value = 0
                with patch("chuk_mcp_client_oauth.cli.asyncio.run") as mock_run:
                    mock_run.return_value = 0
                    result = main()
                    assert result == 0

    def test_main_keyboard_interrupt(self):
        """Test main with keyboard interrupt."""
        with patch("sys.argv", ["cli.py", "get", "test-server"]):
            with patch(
                "chuk_mcp_client_oauth.cli.cmd_get",
                side_effect=KeyboardInterrupt(),
            ):
                result = main()
                assert result == 130

    def test_main_exception(self):
        """Test main with exception."""
        with patch("sys.argv", ["cli.py", "get", "test-server"]):
            with patch(
                "chuk_mcp_client_oauth.cli.cmd_get",
                side_effect=Exception("Test error"),
            ):
                result = main()
                assert result == 1

    def test_main_auth_with_scopes(self):
        """Test main with auth command and scopes."""
        with patch(
            "sys.argv",
            [
                "cli.py",
                "auth",
                "test-server",
                "https://test.com",
                "--scopes",
                "read",
                "write",
            ],
        ):
            with patch(
                "chuk_mcp_client_oauth.cli.cmd_auth", new_callable=AsyncMock
            ) as mock_auth:
                mock_auth.return_value = 0
                with patch("chuk_mcp_client_oauth.cli.asyncio.run") as mock_run:
                    mock_run.return_value = 0
                    result = main()
                    assert result == 0

    def test_main_invalid_command(self):
        """Test main with invalid command."""
        with patch("sys.argv", ["cli.py", "invalid"]):
            # argparse will raise SystemExit with code 2 for invalid command
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 2

    def test_main_entry_point(self):
        """Test __main__ entry point."""
        # Test that the if __name__ == "__main__" block works
        import subprocess
        import sys

        # Run the CLI module as a script
        result = subprocess.run(
            [sys.executable, "-m", "chuk_mcp_client_oauth.cli", "--help"],
            capture_output=True,
            text=True,
        )

        # Should exit successfully with help text
        assert result.returncode == 0
        assert "OAuth Token Manager CLI" in result.stdout
