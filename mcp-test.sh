#!/bin/bash

echo "--- 🐳 Starting Docker MCP Health Check ---"
echo "1. Checking Docker Daemon and Gateway status..."

# Try to list tools; this verifies Docker is running and the gateway is working.
# The tool should be available if Sequential Thinking is enabled in Docker Desktop.
TOOLS_OUTPUT=$(docker mcp tools ls 2>&1)
if echo "$TOOLS_OUTPUT" | grep -q "sequential-thinking"; then
    echo "   ✅ Docker MCP Gateway is running and 'sequential-thinking' tool is available."
else
    echo "   ❌ ERROR: Docker MCP Gateway or Docker Daemon is not running, or 'sequential-thinking' is disabled."
    echo "   Output: $TOOLS_OUTPUT"
    echo "   Action: Please ensure Docker Desktop is running and the Sequential Thinking server is Enabled in the MCP Toolkit Catalog."
    exit 1
fi

echo "---"
echo "2. Checking Claude CLI Configuration Status..."

# Run claude mcp list to verify the connection status
CLAUDE_OUTPUT=$(claude mcp list 2>&1)

if echo "$CLAUDE_OUTPUT" | grep -q "MCP_DOCKER.*Connected"; then
    echo "   ✅ Claude CLI is successfully connected to MCP_DOCKER."
else
    echo "   ❌ ERROR: Claude CLI failed to connect to MCP_DOCKER."
    echo "   Output: $CLAUDE_OUTPUT"
    echo "   Action: Rerunning configuration command now..."
    
    # Re-run the configuration command to ensure it is in the correct file
    claude mcp add --transport stdio MCP_DOCKER docker mcp gateway run > /dev/null 2>&1
    
    # Re-test the connection
    CLAUDE_OUTPUT=$(claude mcp list 2>&1)
    if echo "$CLAUDE_OUTPUT" | grep -q "MCP_DOCKER.*Connected"; then
        echo "   ✅ Reconfiguration successful. Claude CLI is now connected."
    else
        echo "   🛑 FATAL ERROR: Failed to connect even after reconfiguration. See output above."
        exit 1
    fi
fi

echo "---"
echo "3. Testing Sequential Thinking Tool Usage..."

# Use the tool in a simple query
TEST_QUERY='Using the **sequential-thinking** tool, provide a 2-step plan for this test.'
TEST_RESPONSE=$(claude "$TEST_QUERY" 2>&1)

if echo "$TEST_RESPONSE" | grep -q "1." && echo "$TEST_RESPONSE" | grep -q "2."; then
    echo "   ✅ Sequential Thinking tool successfully executed."
    echo "   First 3 Lines of Plan:"
    echo "$TEST_RESPONSE" | head -n 3
else
    echo "   ❌ ERROR: Tool executed but did not return expected sequential output."
    echo "   Full Response: $TEST_RESPONSE"
fi

echo "--- ✅ All Checks Complete ---"
