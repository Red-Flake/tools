### Optional MCP Server (Web UI / API)
This project includes `lwp_mcp_server.py`, a Python-based server that provides an interactive web UI (via any MCP-compatible client) and an API to browse and execute linWinPwn commands.

#### Installation
The server requires Python3 and the official MCP SDK.

```bash
# Install the required Python library
cd /opt/lwp-scripts
python3 -m venv mcp-env
source ./mcp-env/bin/activate
pip3 install mcp.server
```

#### Running the Server

You must have linWinPwn.sh available. The server will look for it in the same directory by default.

```bash
#Run the server
/opt/lwp-scripts/mcp-env/bin/python3 lwp_mcp_server.py
```

The server can be configured with environment variables:

- LWP_PATH: Path to your linWinPwn.sh script (Default: ./linWinPwn.sh).
- LWP_OUTPUT: Path to store all command logs (Default: ./lwp_output).
- MCP_HOST: Host address for the server (Default: 127.0.0.1).
- MCP_PORT: Port for the server (Default: 8000).

Example with custom paths:

```bash
export LWP_PATH="/opt/linWinPwn/linWinPwn.sh"
export LWP_OUTPUT="/tmp"
export MCP_HOST="0.0.0.0"
export MCP_PORT="8000"
/opt/lwp-scripts/mcp-env/bin/python3 lwp_mcp_server.py
```

#### Usage

Once the server is running, you can connect to it using any MCP client, such as the official web interface, by pointing it to the server's address (e.g., http://127.0.0.1:8000/mcp).

This interface allows you to:

- List and search all available run_command entries.
- View default script variables.
- Execute commands remotely, providing custom environment variables.
- View command output, logs, and artifacts in real-time.

#### Client Configuration Example:

The following is an example configuration for integrating the linwinpwn-http MCP server into a client that uses the shared MCP Server configuration format (such as the settings used by the Gemini/Google AI client or certain specialized desktop tools).

This snippet should be added directly in your client's settings file (e.g., in a file like .gemini/settings.json or .vscode/mcp.json).

The configuration instructs the client to connect to your running server via Streamable HTTP.

Configuration Snippet
```JSON
{
  "mcpServers": {
    "linwinpwn": {
      "httpUrl": "http://127.0.0.1:8000/mcp",
      "timeout": 600000,
      "trust": false
    }
  }
}

{
  "servers": {
    "linwinpwn": {
      "type": "http",
      "url": "http://127.0.0.1:8000/mcp"
    }
  }
}
```
