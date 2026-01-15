# ELK Stack Discrete Installation (Windows)

This folder contains PowerShell scripts for installing and configuring the ELK Stack (Elasticsearch, Kibana, and Logstash) as Windows services on a local machine, without using Docker.

## Contents

- **1-Download.ps1** - Downloads Elasticsearch, Kibana, and Logstash binaries
- **2-Configure.ps1** - Configures and creates Windows services
- **Uninstall.ps1** - Removes ELK Stack services and components
- **elasticsearch/** - Elasticsearch configuration files
- **kibana/** - Kibana configuration files
- **logstash/** - Logstash configuration files and pipelines
- **setup/** - Kibana saved objects and role definitions

## Quick Start

### Prerequisites

- Windows 10/11 or Windows Server
- PowerShell 5.1 or higher (run as Administrator)
- Sufficient disk space (minimum 2-3 GB)
- DBMaestro PostgreSQL database details

### Installation Steps

1. **Download Components**
   ```powershell
   .\1-Download.ps1 -Version 9.2.3 -Path "C:\DBmaestroELK"
   ```
   
   Optional parameters:
   - `-Version`: Elastic Stack version (default: 9.2.3)
   - `-Path`: Installation directory (default: C:\DBmaestroELK)
   - `-Force`: Re-download even if already installed

2. **Configure and Create Services**
   ```powershell
   .\2-Configure.ps1 -Path "C:\DBmaestroELK"
   ```
   
   Optional parameters:
   - `-ElasticPassword`: Password for 'elastic' user
   - `-KibanaPassword`: Password for 'kibana_system' user (default: changeme)
   - `-LogstashPassword`: Password for 'logstash_internal' user (default: changeme)

3. **Verify Installation**
   - Elasticsearch: http://localhost:9200
   - Kibana: http://localhost:5601
   - Logstash: Check Windows Services for running status

### Uninstall

To remove the ELK Stack:
```powershell
.\Uninstall.ps1 -Path "C:\DBmaestroELK"
```

## Configuration

### Elasticsearch
- Config: `elasticsearch/config/elasticsearch.yml`
- JVM Options: `elasticsearch/config/jvm.options`

### Kibana
- Config: `kibana/config/kibana.yml`

### Logstash
- Config: `logstash/config/logstash.yml`
- Pipelines: `logstash/config/pipelines.yml`
- Pipeline definitions: `logstash/pipeline/*.conf`

## DBMaestro Integration

The Logstash pipelines are configured to import data from DBMaestro PostgreSQL database:

- **import_activity_info.conf** - Activity logs
- **import_deployment_info.conf** - Deployment information
- **import_drifts_info.conf** - Configuration drifts
- **import_leadtime_info.conf** - Lead time metrics
- **import_objects_info.conf** - Managed objects
- **import_policies_info.conf** - Policies
- **import_restore_time.conf** - Restore time metrics
- **import_scripts_info.conf** - Scripts
- **import_todo_info.conf** - To-do items
- **import_transitiontime_info.conf** - Transition time metrics

## Ports

Default ports used by the stack:

- **9200** - Elasticsearch HTTP
- **9300** - Elasticsearch TCP transport
- **5601** - Kibana web interface
- **5044** - Logstash Beats input
- **50000** - Logstash TCP input
- **9600** - Logstash monitoring API

## Notes

- Run PowerShell scripts as Administrator
- Initial setup may take several minutes
- Ensure firewall allows the required ports
- Monitor logs for any configuration issues
