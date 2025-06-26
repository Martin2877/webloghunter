# WebLogHunter

WebLogHunter is a powerful tool for analyzing and replaying web server logs, designed to help security professionals and developers identify potential HTTP attacks and suspicious activities in web server logs.

[English](README.md) | [简体中文](README_CN.md)

## Workflow

```mermaid
flowchart TD
    subgraph Replay[Replay Mode]
        A[Log Files] -->|Input| B[WebLogHunter]
        B -->|Replay| C[Test Host]
    end
    
    subgraph Detection[Detection Mode]
        D[Log Files] -->|Input| E[WebLogHunter]
        E -->|Apply| F[Detection Rules]
        F -->|Generate| G[Results]
    end
    
    style Replay fill:#f5f5f5,stroke:#333,stroke-width:2px
    style Detection fill:#f5f5f5,stroke:#333,stroke-width:2px
    style A fill:#d4f1f9,stroke:#333
    style D fill:#d4f1f9,stroke:#333
    style C fill:#d5f5e3,stroke:#333
    style G fill:#d5f5e3,stroke:#333
```


## Features

- **Log Replay**: Replay HTTP requests from log files to test server responses
- **Attack Detection**: Identify potential security threats using customizable rules
- **Multiple Log Formats**: Supports common web server log formats (Nginx, Apache, etc.)
- **Custom Rules**: Define your own detection rules for specific attack patterns
- **Performance Testing**: Stress test your web applications by replaying real traffic

## Installation

### Prerequisites
- Go 1.16 or higher

### Using Go Install
```bash
go install github.com/martin2877/webloghunter@latest
```

### Building from Source
```bash
git clone https://github.com/martin2877/webloghunter.git
cd webloghunter
go build -o webloghunter
```

## Usage

### Web Log Replay
Replay HTTP requests from log files to a target server:

```bash
# Basic usage
webloghunter replay -l /path/to/access.log -t http://target-server
```

### Web Log Detection
Analyze logs for potential security threats using built-in or custom rules:

```bash
# Basic detection
webloghunter detection -l /path/to/access.log

# With custom rules file
webloghunter detection -l access.log -c rules.custom.yaml
```

## Configuration

Create a `config.yaml` file to customize WebLogHunter's behavior:

```yaml
# rules.yaml
attackregex:
  - id: 1
    regex: '.*xwork\.MethodAccessor.*'
    place: 'url'
    typename: 'Exploit Pattern'
    level: 3
    leveldesc: 'High Severity Threat'
    actiondesc: 'Struts2 Remote Code Execution Vulnerability'

scannerregex:
  - regex: '.*?HTTrack.*?'
    typename: 'HTTrack'
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

