# NetQuery

<p align="center">
  <img src="docs/logo.png" width="200px"/>
</p>

NetQuery is a Rust-based daemon (`netqueryd`) that listens to live network traffic (layers 1-4), maintains rolling matrices of flows in memory, and exposes a natural-language "ask" interface (CLI + gRPC).

> **Note:** This is an initial draft of NetQuery. Local LLM models and enhanced features will be added soon.


# Demo

[![Voir la démo sur asciinema](https://asciinema.org/a/dXQYPPpclgEXbmbKgwvi7ieCp.svg)](https://asciinema.org/a/dXQYPPpclgEXbmbKgwvi7ieCp)


## Features

- Packet capture with support for high-speed networks (1+ Gbit/s)
- Live network traffic analysis with minimal memory footprint
- Natural language query interface (English and French)
- Smart multi-turn querying with self-correction for better answers
- Rolling windows of flow data for efficient querying
- gRPC API for integrations
- Command-line interface with interactive mode and progress indicators


## Usage

### Command Line

```bash
# Ask a simple question - shows a spinner while thinking
netquery ask.llm "Top 3 IP port 80"

# Get daemon status
netquery status

# Get metrics
netquery metrics

# Interactive mode with smart queries
netquery interactive
```

### Examples

```bash
# Basic queries
netquery ask.llm "Show me the top 10 IPs by traffic"
netquery ask.llm "What are the most active source ports?"
netquery ask.llm "Show traffic to destination port 443"

# Complex queries (multi-turn)
netquery ask.llm "What unusual traffic patterns have occurred in the last 24 hours?"
netquery ask.llm "Are there any hosts communicating on uncommon ports?"

```