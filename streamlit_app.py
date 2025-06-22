import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
from datetime import datetime, timedelta
import json
import time
import warnings
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import joblib
import asyncio
import threading
from typing import Dict, List, Any, Optional
import logging
import requests
import hashlib
import hmac
import base64
from urllib.parse import quote

# Try to import SQL Server connectivity libraries
try:
    import pyodbc
    PYODBC_AVAILABLE = True
except ImportError:
    PYODBC_AVAILABLE = False
    pyodbc = None

try:
    import sqlalchemy
    from sqlalchemy import create_engine, text
    SQLALCHEMY_AVAILABLE = True
except ImportError:
    SQLALCHEMY_AVAILABLE = False
    sqlalchemy = None

try:
    from anthropic import Anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False
    Anthropic = None

warnings.filterwarnings('ignore')

# Configure Streamlit page
st.set_page_config(
    page_title="Enterprise SQL Server AI Monitor",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for enterprise UI
st.markdown("""
<style>
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 12px;
        color: white;
        margin: 0.5rem 0;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
    }
    .server-status-online {
        background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
        padding: 1rem;
        border-radius: 8px;
        color: white;
        margin: 0.3rem 0;
    }
    .server-status-offline {
        background: linear-gradient(135deg, #ff416c 0%, #ff4757 100%);
        padding: 1rem;
        border-radius: 8px;
        color: white;
        margin: 0.3rem 0;
    }
    .alert-critical {
        background: linear-gradient(135deg, #ff416c 0%, #ff4757 100%);
        color: white;
        padding: 1rem;
        border-radius: 8px;
        margin: 0.3rem 0;
        border-left: 5px solid #c0392b;
    }
    .alert-warning {
        background: linear-gradient(135deg, #f39c12 0%, #f1c40f 100%);
        color: white;
        padding: 1rem;
        border-radius: 8px;
        margin: 0.3rem 0;
        border-left: 5px solid #e67e22;
    }
    .alert-info {
        background: linear-gradient(135deg, #3498db 0%, #2980b9 100%);
        color: white;
        padding: 1rem;
        border-radius: 8px;
        margin: 0.3rem 0;
        border-left: 5px solid #2c3e50;
    }
    .claude-insight {
        background: linear-gradient(135deg, #8e44ad 0%, #9b59b6 100%);
        color: white;
        padding: 1.5rem;
        border-radius: 12px;
        margin: 1rem 0;
        border-left: 5px solid #6c3483;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 2px;
    }
    .stTabs [data-baseweb="tab"] {
        height: 60px;
        padding-left: 25px;
        padding-right: 25px;
        background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
        border-radius: 8px 8px 0 0;
    }
</style>
""", unsafe_allow_html=True)

# =================== SQL Server Connection Manager ===================
class SQLServerConnector:
    def __init__(self, server_configs: List[Dict]):
        """Initialize SQL Server connections"""
        self.server_configs = server_configs
        self.connections = {}
        self.connection_status = {}
        self.demo_mode = not PYODBC_AVAILABLE
        
        if not PYODBC_AVAILABLE:
            st.warning("⚠️ Running in Demo Mode: pyodbc not available. Install pyodbc and ODBC drivers for real SQL Server connections.")
        
    def test_connection(self, server_config: Dict) -> bool:
        """Test connection to SQL Server"""
        if self.demo_mode:
            # Simulate connection test in demo mode
            return True
            
        try:
            if PYODBC_AVAILABLE:
                connection_string = (
                    f"DRIVER={{ODBC Driver 18 for SQL Server}};"
                    f"SERVER={server_config['server']};"
                    f"DATABASE={server_config['database']};"
                    f"UID={server_config['username']};"
                    f"PWD={server_config['password']};"
                    f"TrustServerCertificate=yes;"
                    f"Connection Timeout=10;"
                )
                
                conn = pyodbc.connect(connection_string)
                cursor = conn.cursor()
                cursor.execute("SELECT 1")
                cursor.close()
                conn.close()
                return True
            else:
                return False
            
        except Exception as e:
            st.error(f"Connection failed for {server_config['name']}: {str(e)}")
            return False
    
    def get_connection(self, server_name: str):
        """Get database connection for a server"""
        if self.demo_mode:
            return None
            
        server_config = next((s for s in self.server_configs if s['name'] == server_name), None)
        if not server_config:
            return None
            
        try:
            if PYODBC_AVAILABLE:
                connection_string = (
                    f"DRIVER={{ODBC Driver 18 for SQL Server}};"
                    f"SERVER={server_config['server']};"
                    f"DATABASE={server_config['database']};"
                    f"UID={server_config['username']};"
                    f"PWD={server_config['password']};"
                    f"TrustServerCertificate=yes;"
                    f"Connection Timeout=30;"
                )
                
                return pyodbc.connect(connection_string)
            else:
                return None
            
        except Exception as e:
            st.error(f"Failed to connect to {server_name}: {str(e)}")
            return None
    
    def execute_query(self, server_name: str, query: str) -> pd.DataFrame:
        """Execute query and return results as DataFrame"""
        if self.demo_mode:
            # Return demo data
            return self._generate_demo_data(query)
            
        conn = self.get_connection(server_name)
        if not conn:
            return pd.DataFrame()
        
        try:
            df = pd.read_sql(query, conn)
            conn.close()
            return df
        except Exception as e:
            st.error(f"Query execution failed on {server_name}: {str(e)}")
            if conn:
                conn.close()
            return pd.DataFrame()
    
    def _generate_demo_data(self, query: str) -> pd.DataFrame:
        """Generate demo data based on query type"""
        current_time = datetime.now()
        
        if 'system_metrics' in query:
            return pd.DataFrame({
                'timestamp': [current_time],
                'processor_queue_length': [2],
                'buffer_cache_hit_ratio': [np.random.uniform(90, 99)],
                'page_life_expectancy': [np.random.uniform(300, 3000)],
                'target_pages': [1000000],
                'total_pages': [950000]
            })
        
        elif 'wait_stats' in query:
            wait_types = ['CXPACKET', 'ASYNC_NETWORK_IO', 'PAGEIOLATCH_SH', 'LCK_M_S', 'WRITELOG']
            return pd.DataFrame({
                'wait_type': wait_types,
                'waiting_tasks_count': np.random.randint(1, 100, 5),
                'wait_time_ms': np.random.randint(100, 10000, 5),
                'max_wait_time_ms': np.random.randint(500, 5000, 5),
                'signal_wait_time_ms': np.random.randint(10, 500, 5)
            })
        
        elif 'active_connections' in query:
            return pd.DataFrame({
                'total_connections': [np.random.randint(50, 200)],
                'running_sessions': [np.random.randint(5, 50)],
                'sleeping_sessions': [np.random.randint(20, 100)],
                'suspended_sessions': [np.random.randint(0, 10)]
            })
        
        elif 'cpu_utilization' in query:
            records = []
            for i in range(30):
                records.append({
                    'record_id': i,
                    'EventTime': current_time - timedelta(minutes=i),
                    'SQLProcessUtilization': np.random.uniform(20, 80),
                    'SystemIdle': np.random.uniform(10, 40),
                    'OtherProcessUtilization': np.random.uniform(5, 30)
                })
            return pd.DataFrame(records)
        
        elif 'memory_usage' in query:
            return pd.DataFrame({
                'physical_memory_mb': [16384],
                'virtual_memory_mb': [2097151],
                'committed_memory_mb': [8192],
                'committed_target_mb': [12288],
                'visible_target_mb': [16384]
            })
        
        elif 'blocking_sessions' in query:
            # Sometimes return empty (no blocking), sometimes return data
            if np.random.random() > 0.7:
                return pd.DataFrame({
                    'blocking_session_id': [52, 73],
                    'session_id': [125, 134],
                    'wait_type': ['LCK_M_X', 'LCK_M_S'],
                    'wait_time': [5000, 2000],
                    'wait_resource': ['PAGE: 5:1:12345', 'KEY: 6:72057594037927936'],
                    'command': ['SELECT', 'UPDATE'],
                    'status': ['suspended', 'suspended'],
                    'cpu_time': [100, 250],
                    'logical_reads': [1000, 2500],
                    'reads': [10, 25],
                    'writes': [5, 15]
                })
            else:
                return pd.DataFrame()
        
        elif 'database_sizes' in query:
            databases = ['ProductionDB', 'UserDB', 'LogDB', 'AnalyticsDB']
            data = []
            for db in databases:
                data.extend([
                    {
                        'database_name': db,
                        'type_desc': 'ROWS',
                        'size_mb': np.random.uniform(1000, 10000),
                        'max_size_mb': -1,
                        'growth': 10,
                        'is_percent_growth': True
                    },
                    {
                        'database_name': db,
                        'type_desc': 'LOG',
                        'size_mb': np.random.uniform(100, 1000),
                        'max_size_mb': -1,
                        'growth': 10,
                        'is_percent_growth': True
                    }
                ])
            return pd.DataFrame(data)
        
        elif 'index_fragmentation' in query:
            # Sometimes return fragmented indexes
            if np.random.random() > 0.5:
                return pd.DataFrame({
                    'schema_name': ['dbo', 'sales', 'dbo'],
                    'object_name': ['Orders', 'Customers', 'Products'],
                    'index_name': ['IX_Orders_Date', 'PK_Customers', 'IX_Products_Category'],
                    'index_type_desc': ['NONCLUSTERED INDEX', 'CLUSTERED INDEX', 'NONCLUSTERED INDEX'],
                    'avg_fragmentation_in_percent': [45.2, 67.8, 52.1],
                    'page_count': [2500, 5000, 1800]
                })
            else:
                return pd.DataFrame()
        
        elif 'disk_io' in query:
            databases = ['ProductionDB', 'UserDB', 'LogDB']
            data = []
            for db in databases:
                data.extend([
                    {
                        'database_name': db,
                        'physical_name': f'C:\\Data\\{db}.mdf',
                        'num_of_reads': np.random.randint(10000, 100000),
                        'num_of_writes': np.random.randint(5000, 50000),
                        'mb_read': np.random.uniform(100, 1000),
                        'mb_written': np.random.uniform(50, 500),
                        'io_stall_read_ms': np.random.randint(1000, 10000),
                        'io_stall_write_ms': np.random.randint(500, 5000)
                    },
                    {
                        'database_name': db,
                        'physical_name': f'C:\\Logs\\{db}_log.ldf',
                        'num_of_reads': np.random.randint(1000, 10000),
                        'num_of_writes': np.random.randint(10000, 100000),
                        'mb_read': np.random.uniform(10, 100),
                        'mb_written': np.random.uniform(100, 1000),
                        'io_stall_read_ms': np.random.randint(100, 1000),
                        'io_stall_write_ms': np.random.randint(1000, 10000)
                    }
                ])
            return pd.DataFrame(data)
        
        elif 'backup_status' in query:
            databases = ['ProductionDB', 'UserDB', 'LogDB', 'AnalyticsDB']
            data = []
            for db in databases:
                last_full = current_time - timedelta(hours=np.random.uniform(1, 48))
                last_diff = current_time - timedelta(hours=np.random.uniform(1, 24))
                last_log = current_time - timedelta(minutes=np.random.uniform(15, 240))
                
                data.append({
                    'database_name': db,
                    'recovery_model_desc': np.random.choice(['FULL', 'SIMPLE', 'BULK_LOGGED']),
                    'last_full_backup': last_full,
                    'last_diff_backup': last_diff,
                    'last_log_backup': last_log
                })
            return pd.DataFrame(data)
        
        else:
            # Default empty dataframe
            return pd.DataFrame()

# =================== SQL Server Metrics Collector ===================
class SQLServerMetricsCollector:
    def __init__(self, sql_connector: SQLServerConnector):
        self.sql_connector = sql_connector
        
        # Comprehensive SQL Server monitoring queries
        self.queries = {
            'system_metrics': """
                SELECT 
                    GETDATE() as timestamp,
                    (SELECT counter_value FROM sys.dm_os_performance_counters 
                     WHERE counter_name = 'Processor Queue Length') as processor_queue_length,
                    (SELECT cntr_value FROM sys.dm_os_performance_counters 
                     WHERE counter_name = 'Buffer cache hit ratio') as buffer_cache_hit_ratio,
                    (SELECT cntr_value FROM sys.dm_os_performance_counters 
                     WHERE counter_name = 'Page life expectancy') as page_life_expectancy,
                    (SELECT cntr_value FROM sys.dm_os_performance_counters 
                     WHERE counter_name = 'Target pages') as target_pages,
                    (SELECT cntr_value FROM sys.dm_os_performance_counters 
                     WHERE counter_name = 'Total pages') as total_pages
            """,
            
            'wait_stats': """
                SELECT TOP 10
                    wait_type,
                    waiting_tasks_count,
                    wait_time_ms,
                    max_wait_time_ms,
                    signal_wait_time_ms
                FROM sys.dm_os_wait_stats
                WHERE wait_type NOT IN (
                    'CLR_SEMAPHORE', 'LAZYWRITER_SLEEP', 'RESOURCE_QUEUE', 'SLEEP_TASK',
                    'SLEEP_SYSTEMTASK', 'SQLTRACE_WAIT', 'WAITFOR', 'BROKER_TASK_STOP',
                    'CHECKPOINT_QUEUE', 'FT_IFTS_SCHEDULER_IDLE_WAIT', 'XE_DISPATCHER_WAIT'
                )
                ORDER BY wait_time_ms DESC
            """,
            
            'blocking_sessions': """
                SELECT 
                    blocking_session_id,
                    session_id,
                    wait_type,
                    wait_time,
                    wait_resource,
                    command,
                    status,
                    cpu_time,
                    logical_reads,
                    reads,
                    writes
                FROM sys.dm_exec_requests
                WHERE blocking_session_id <> 0
            """,
            
            'database_sizes': """
                SELECT 
                    DB_NAME(database_id) AS database_name,
                    type_desc,
                    size * 8.0 / 1024 AS size_mb,
                    max_size * 8.0 / 1024 AS max_size_mb,
                    growth,
                    is_percent_growth
                FROM sys.master_files
                WHERE database_id > 4
            """,
            
            'index_fragmentation': """
                SELECT 
                    OBJECT_SCHEMA_NAME(ips.object_id) AS schema_name,
                    OBJECT_NAME(ips.object_id) AS object_name,
                    i.name AS index_name,
                    ips.index_type_desc,
                    ips.avg_fragmentation_in_percent,
                    ips.page_count
                FROM sys.dm_db_index_physical_stats(DB_ID(), NULL, NULL, NULL, 'SAMPLED') ips
                JOIN sys.indexes i ON ips.object_id = i.object_id AND ips.index_id = i.index_id
                WHERE ips.avg_fragmentation_in_percent > 30 AND ips.page_count > 1000
                ORDER BY ips.avg_fragmentation_in_percent DESC
            """,
            
            'active_connections': """
                SELECT 
                    COUNT(*) as total_connections,
                    SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) as running_sessions,
                    SUM(CASE WHEN status = 'sleeping' THEN 1 ELSE 0 END) as sleeping_sessions,
                    SUM(CASE WHEN status = 'suspended' THEN 1 ELSE 0 END) as suspended_sessions
                FROM sys.dm_exec_sessions
                WHERE is_user_process = 1
            """,
            
            'cpu_utilization': """
                DECLARE @cpu_count int
                SELECT @cpu_count = cpu_count FROM sys.dm_os_sys_info
                
                SELECT TOP 30
                    record_id,
                    DateAdd(ms, -1 * (@cpu_count - record_id), GetDate()) AS EventTime,
                    SQLProcessUtilization,
                    SystemIdle,
                    100 - SystemIdle - SQLProcessUtilization AS OtherProcessUtilization
                FROM (
                    SELECT 
                        record.value('(./Record/@id)[1]', 'int') AS record_id,
                        record.value('(./Record/SchedulerMonitorEvent/SystemHealth/SystemIdle)[1]', 'int') AS SystemIdle,
                        record.value('(./Record/SchedulerMonitorEvent/SystemHealth/ProcessUtilization)[1]', 'int') AS SQLProcessUtilization
                    FROM (
                        SELECT CAST(record AS xml) AS record 
                        FROM sys.dm_os_ring_buffers 
                        WHERE ring_buffer_type = N'RING_BUFFER_SCHEDULER_MONITOR'
                        AND record LIKE N'%<SystemHealth>%'
                    ) AS x
                ) AS y
                ORDER BY record_id DESC
            """,
            
            'memory_usage': """
                SELECT 
                    (physical_memory_kb / 1024.0) AS physical_memory_mb,
                    (virtual_memory_kb / 1024.0) AS virtual_memory_mb,
                    (committed_kb / 1024.0) AS committed_memory_mb,
                    (committed_target_kb / 1024.0) AS committed_target_mb,
                    (visible_target_kb / 1024.0) AS visible_target_mb
                FROM sys.dm_os_sys_memory
            """,
            
            'disk_io': """
                SELECT 
                    DB_NAME(vfs.database_id) AS database_name,
                    mf.physical_name,
                    vfs.num_of_reads,
                    vfs.num_of_writes,
                    vfs.num_of_bytes_read / 1024 / 1024 AS mb_read,
                    vfs.num_of_bytes_written / 1024 / 1024 AS mb_written,
                    vfs.io_stall_read_ms,
                    vfs.io_stall_write_ms
                FROM sys.dm_io_virtual_file_stats(NULL, NULL) vfs
                JOIN sys.master_files mf ON vfs.database_id = mf.database_id 
                    AND vfs.file_id = mf.file_id
                WHERE vfs.database_id > 4
            """,
            
            'backup_status': """
                SELECT 
                    d.name AS database_name,
                    d.recovery_model_desc,
                    COALESCE(
                        (SELECT MAX(backup_finish_date) 
                         FROM msdb.dbo.backupset bs 
                         WHERE bs.database_name = d.name AND bs.type = 'D'),
                        '1900-01-01'
                    ) AS last_full_backup,
                    COALESCE(
                        (SELECT MAX(backup_finish_date) 
                         FROM msdb.dbo.backupset bs 
                         WHERE bs.database_name = d.name AND bs.type = 'I'),
                        '1900-01-01'
                    ) AS last_diff_backup,
                    COALESCE(
                        (SELECT MAX(backup_finish_date) 
                         FROM msdb.dbo.backupset bs 
                         WHERE bs.database_name = d.name AND bs.type = 'L'),
                        '1900-01-01'
                    ) AS last_log_backup
                FROM sys.databases d
                WHERE d.database_id > 4 AND d.state = 0
            """
        }
    
    def collect_all_metrics(self, server_name: str) -> Dict[str, pd.DataFrame]:
        """Collect all metrics from a SQL Server instance"""
        metrics = {}
        
        for metric_name, query in self.queries.items():
            try:
                df = self.sql_connector.execute_query(server_name, query)
                if not df.empty:
                    metrics[metric_name] = df
                else:
                    metrics[metric_name] = pd.DataFrame()
            except Exception as e:
                st.warning(f"Failed to collect {metric_name} from {server_name}: {str(e)}")
                metrics[metric_name] = pd.DataFrame()
        
        return metrics
    
    def get_health_summary(self, server_name: str) -> Dict[str, Any]:
        """Get a comprehensive health summary for a server"""
        try:
            if self.sql_connector.demo_mode:
                # Generate demo health summary
                return {
                    "status": "online",
                    "server_name": server_name,
                    "sql_version": "Microsoft SQL Server 2019 (RTM) - 15.0.2000.5",
                    "product_version": "15.0.2000.5",
                    "edition": "Developer Edition (64-bit)",
                    "product_level": "RTM",
                    "current_time": datetime.now(),
                    "online_databases": np.random.randint(4, 12),
                    "user_sessions": np.random.randint(10, 50),
                    "last_check": datetime.now()
                }
            
            # Get basic server info
            server_info_query = """
                SELECT 
                    @@SERVERNAME as server_name,
                    @@VERSION as sql_version,
                    SERVERPROPERTY('ProductVersion') as product_version,
                    SERVERPROPERTY('Edition') as edition,
                    SERVERPROPERTY('ProductLevel') as product_level,
                    GETDATE() as current_time,
                    (SELECT COUNT(*) FROM sys.databases WHERE state = 0) as online_databases,
                    (SELECT COUNT(*) FROM sys.dm_exec_sessions WHERE is_user_process = 1) as user_sessions
            """
            
            server_info = self.sql_connector.execute_query(server_name, server_info_query)
            
            if server_info.empty:
                return {"status": "offline", "error": "No data returned"}
            
            info = server_info.iloc[0].to_dict()
            info["status"] = "online"
            info["last_check"] = datetime.now()
            
            return info
            
        except Exception as e:
            return {"status": "offline", "error": str(e), "last_check": datetime.now()}

# =================== Claude AI Integration ===================
class ClaudeAIAnalyzer:
    def __init__(self, api_key: str):
        """Initialize Claude AI client"""
        if not ANTHROPIC_AVAILABLE:
            self.client = None
            self.enabled = False
            st.warning("⚠️ Anthropic library not available. Install 'anthropic' package for AI features.")
            return
            
        if api_key and api_key != "your_claude_api_key_here":
            try:
                self.client = Anthropic(api_key=api_key)
                self.enabled = True
            except Exception as e:
                self.client = None
                self.enabled = False
                st.error(f"Failed to initialize Claude AI: {str(e)}")
        else:
            self.client = None
            self.enabled = False
    
    def analyze_performance_metrics(self, server_metrics: Dict[str, Dict]) -> Dict[str, str]:
        """Use Claude AI to analyze performance metrics across all servers"""
        if not self.enabled:
            return {"analysis": "Claude AI not configured", "recommendations": "Configure Claude AI API key in sidebar"}
        
        try:
            # Prepare metrics summary for Claude
            metrics_summary = self._prepare_metrics_summary(server_metrics)
            
            prompt = f"""
            As a SQL Server performance expert, analyze the following real-time metrics from a multi-server environment and provide:
            
            1. Overall health assessment
            2. Critical issues that need immediate attention
            3. Performance bottlenecks
            4. Proactive recommendations
            5. Risk assessment for each server
            
            Server Metrics Data:
            {metrics_summary}
            
            Focus on:
            - CPU and memory utilization patterns
            - Blocking and wait statistics
            - Index fragmentation issues
            - Backup compliance
            - Disk I/O performance
            - Buffer cache efficiency
            
            Provide actionable insights in a structured format.
            """
            
            response = self.client.messages.create(
                model="claude-3-sonnet-20240229",
                max_tokens=1500,
                messages=[{"role": "user", "content": prompt}]
            )
            
            analysis = response.content[0].text
            
            # Parse response into sections
            sections = self._parse_claude_response(analysis)
            return sections
            
        except Exception as e:
            return {"analysis": f"Claude AI analysis failed: {str(e)}", "recommendations": "Check API configuration"}
    
    def predict_failures(self, historical_data: Dict, current_metrics: Dict) -> Dict[str, Any]:
        """Use Claude AI to predict potential failures"""
        if not self.enabled:
            return {"predictions": "Claude AI not configured"}
        
        try:
            data_summary = self._prepare_failure_prediction_data(historical_data, current_metrics)
            
            prompt = f"""
            As a SQL Server reliability expert, analyze the following historical and current performance data to predict potential failures:
            
            Data Summary:
            {data_summary}
            
            Provide:
            1. Failure probability for each server (0-100%)
            2. Most likely failure scenarios
            3. Time-to-failure estimates
            4. Prevention strategies
            5. Risk mitigation steps
            
            Focus on patterns that typically lead to:
            - Memory pressure
            - Disk space exhaustion
            - Deadlock scenarios
            - Performance degradation
            - Service outages
            """
            
            response = self.client.messages.create(
                model="claude-3-sonnet-20240229",
                max_tokens=1200,
                messages=[{"role": "user", "content": prompt}]
            )
            
            return {"predictions": response.content[0].text}
            
        except Exception as e:
            return {"predictions": f"Prediction analysis failed: {str(e)}"}
    
    def generate_maintenance_plan(self, server_metrics: Dict, alert_history: List) -> str:
        """Generate intelligent maintenance recommendations"""
        if not self.enabled:
            return "Claude AI not configured for maintenance planning"
        
        try:
            context = self._prepare_maintenance_context(server_metrics, alert_history)
            
            prompt = f"""
            As a SQL Server DBA, create a comprehensive maintenance plan based on:
            
            Current System State:
            {context}
            
            Generate a prioritized maintenance plan including:
            1. Immediate actions (next 24 hours)
            2. Short-term tasks (next week)
            3. Long-term improvements (next month)
            4. Preventive measures
            5. Resource optimization opportunities
            
            Include specific SQL Server maintenance tasks like:
            - Index maintenance requirements
            - Statistics updates
            - Database integrity checks
            - Backup strategy optimization
            - Performance tuning recommendations
            """
            
            response = self.client.messages.create(
                model="claude-3-sonnet-20240229",
                max_tokens=1500,
                messages=[{"role": "user", "content": prompt}]
            )
            
            return response.content[0].text
            
        except Exception as e:
            return f"Maintenance plan generation failed: {str(e)}"
    
    def _prepare_metrics_summary(self, server_metrics: Dict) -> str:
        """Prepare a concise summary of metrics for Claude analysis"""
        summary = []
        
        for server_name, metrics in server_metrics.items():
            server_summary = [f"\n{server_name}:"]
            
            # System metrics
            if 'system_metrics' in metrics and not metrics['system_metrics'].empty:
                sys_metrics = metrics['system_metrics'].iloc[0]
                server_summary.append(f"  Buffer Cache Hit Ratio: {sys_metrics.get('buffer_cache_hit_ratio', 'N/A')}")
                server_summary.append(f"  Page Life Expectancy: {sys_metrics.get('page_life_expectancy', 'N/A')}")
            
            # Connection info
            if 'active_connections' in metrics and not metrics['active_connections'].empty:
                conn_metrics = metrics['active_connections'].iloc[0]
                server_summary.append(f"  Total Connections: {conn_metrics.get('total_connections', 'N/A')}")
                server_summary.append(f"  Running Sessions: {conn_metrics.get('running_sessions', 'N/A')}")
            
            # Wait stats
            if 'wait_stats' in metrics and not metrics['wait_stats'].empty:
                top_wait = metrics['wait_stats'].iloc[0]
                server_summary.append(f"  Top Wait Type: {top_wait.get('wait_type', 'N/A')}")
                server_summary.append(f"  Wait Time (ms): {top_wait.get('wait_time_ms', 'N/A')}")
            
            # Blocking
            if 'blocking_sessions' in metrics and not metrics['blocking_sessions'].empty:
                blocking_count = len(metrics['blocking_sessions'])
                server_summary.append(f"  Blocking Sessions: {blocking_count}")
            
            summary.extend(server_summary)
        
        return "\n".join(summary)
    
    def _prepare_failure_prediction_data(self, historical_data: Dict, current_metrics: Dict) -> str:
        """Prepare data for failure prediction analysis"""
        summary = ["Historical Trends and Current State:"]
        
        for server_name in current_metrics.keys():
            summary.append(f"\n{server_name}:")
            summary.append("  Current State: [summarized current metrics]")
            summary.append("  Recent Trends: [historical patterns]")
            # Add more detailed analysis here based on your historical data structure
        
        return "\n".join(summary)
    
    def _prepare_maintenance_context(self, server_metrics: Dict, alert_history: List) -> str:
        """Prepare context for maintenance planning"""
        context = ["System Context for Maintenance Planning:"]
        
        # Recent alerts summary
        if alert_history:
            context.append(f"\nRecent Alerts ({len(alert_history)} total):")
            for alert in alert_history[-5:]:  # Last 5 alerts
                context.append(f"  - {alert.get('severity', 'Unknown')}: {alert.get('message', 'No message')}")
        
        # Current metrics summary
        context.extend(["\nCurrent Server States:"])
        for server_name, metrics in server_metrics.items():
            context.append(f"  {server_name}: [health summary]")
        
        return "\n".join(context)
    
    def _parse_claude_response(self, response: str) -> Dict[str, str]:
        """Parse Claude's response into structured sections"""
        sections = {
            "overall_health": "",
            "critical_issues": "",
            "recommendations": "",
            "risk_assessment": ""
        }
        
        # Simple parsing - in production, you might want more sophisticated parsing
        if "health" in response.lower():
            sections["overall_health"] = response[:500]  # First part
        
        sections["recommendations"] = response[-500:]  # Last part
        
        return sections

# =================== Enhanced Alert Management ===================
class EnterpriseAlertManager:
    def __init__(self):
        self.alert_rules = {
            'cpu_high': {'threshold': 80, 'severity': 'warning', 'duration': 300},
            'cpu_critical': {'threshold': 95, 'severity': 'critical', 'duration': 120},
            'memory_high': {'threshold': 85, 'severity': 'warning', 'duration': 300},
            'memory_critical': {'threshold': 95, 'severity': 'critical', 'duration': 120},
            'buffer_cache_low': {'threshold': 90, 'severity': 'warning', 'duration': 600},
            'page_life_low': {'threshold': 300, 'severity': 'critical', 'duration': 300},
            'blocking_sessions': {'threshold': 0, 'severity': 'warning', 'duration': 60},
            'high_wait_times': {'threshold': 1000, 'severity': 'warning', 'duration': 300},
            'backup_overdue': {'threshold': 24, 'severity': 'critical', 'duration': 0}  # hours
        }
        
        if 'enterprise_alerts' not in st.session_state:
            st.session_state.enterprise_alerts = []
    
    def evaluate_sql_server_alerts(self, server_name: str, metrics: Dict[str, pd.DataFrame], 
                                  health_summary: Dict) -> List[Dict]:
        """Evaluate enterprise-grade alerts for SQL Server"""
        alerts = []
        current_time = datetime.now()
        
        # System health alerts
        if health_summary.get('status') == 'offline':
            alerts.append({
                'timestamp': current_time,
                'server': server_name,
                'severity': 'critical',
                'category': 'connectivity',
                'message': f"Server {server_name} is offline or unreachable",
                'metric': 'connectivity',
                'value': 0,
                'threshold': 1,
                'recommendation': 'Check network connectivity and SQL Server service status'
            })
        
        # Buffer cache hit ratio
        if 'system_metrics' in metrics and not metrics['system_metrics'].empty:
            sys_metrics = metrics['system_metrics'].iloc[0]
            buffer_cache = sys_metrics.get('buffer_cache_hit_ratio', 100)
            
            if buffer_cache < self.alert_rules['buffer_cache_low']['threshold']:
                alerts.append({
                    'timestamp': current_time,
                    'server': server_name,
                    'severity': 'warning',
                    'category': 'performance',
                    'message': f"Low buffer cache hit ratio: {buffer_cache:.1f}%",
                    'metric': 'buffer_cache_hit_ratio',
                    'value': buffer_cache,
                    'threshold': self.alert_rules['buffer_cache_low']['threshold'],
                    'recommendation': 'Consider increasing memory allocation or optimize queries'
                })
            
            # Page life expectancy
            page_life = sys_metrics.get('page_life_expectancy', 3000)
            if page_life < self.alert_rules['page_life_low']['threshold']:
                alerts.append({
                    'timestamp': current_time,
                    'server': server_name,
                    'severity': 'critical',
                    'category': 'memory',
                    'message': f"Low page life expectancy: {page_life:.0f}s",
                    'metric': 'page_life_expectancy',
                    'value': page_life,
                    'threshold': self.alert_rules['page_life_low']['threshold'],
                    'recommendation': 'Immediate memory pressure investigation required'
                })
        
        # Blocking sessions
        if 'blocking_sessions' in metrics and not metrics['blocking_sessions'].empty:
            blocking_count = len(metrics['blocking_sessions'])
            if blocking_count > 0:
                alerts.append({
                    'timestamp': current_time,
                    'server': server_name,
                    'severity': 'warning',
                    'category': 'blocking',
                    'message': f"Blocking detected: {blocking_count} blocked sessions",
                    'metric': 'blocking_sessions',
                    'value': blocking_count,
                    'threshold': 0,
                    'recommendation': 'Investigate and resolve blocking chains'
                })
        
        # High wait times
        if 'wait_stats' in metrics and not metrics['wait_stats'].empty:
            top_wait = metrics['wait_stats'].iloc[0]
            wait_time = top_wait.get('wait_time_ms', 0)
            if wait_time > self.alert_rules['high_wait_times']['threshold']:
                alerts.append({
                    'timestamp': current_time,
                    'server': server_name,
                    'severity': 'warning',
                    'category': 'performance',
                    'message': f"High wait times detected: {top_wait.get('wait_type', 'Unknown')} ({wait_time:.0f}ms)",
                    'metric': 'wait_time',
                    'value': wait_time,
                    'threshold': self.alert_rules['high_wait_times']['threshold'],
                    'recommendation': f"Investigate {top_wait.get('wait_type', 'Unknown')} wait type"
                })
        
        # Backup compliance
        if 'backup_status' in metrics and not metrics['backup_status'].empty:
            for _, backup_row in metrics['backup_status'].iterrows():
                db_name = backup_row.get('database_name', 'Unknown')
                last_full = backup_row.get('last_full_backup')
                
                if last_full and last_full != '1900-01-01':
                    hours_since_backup = (current_time - pd.to_datetime(last_full)).total_seconds() / 3600
                    if hours_since_backup > self.alert_rules['backup_overdue']['threshold']:
                        alerts.append({
                            'timestamp': current_time,
                            'server': server_name,
                            'severity': 'critical',
                            'category': 'backup',
                            'message': f"Backup overdue for {db_name}: {hours_since_backup:.1f}h since last full backup",
                            'metric': 'backup_age',
                            'value': hours_since_backup,
                            'threshold': self.alert_rules['backup_overdue']['threshold'],
                            'recommendation': 'Schedule immediate backup'
                        })
        
        return alerts
    
    def add_alerts(self, alerts: List[Dict]):
        """Add new alerts to session state"""
        st.session_state.enterprise_alerts.extend(alerts)
        # Keep only last 200 alerts
        st.session_state.enterprise_alerts = st.session_state.enterprise_alerts[-200:]
    
    def get_alerts_by_category(self, hours: int = 24) -> Dict[str, List[Dict]]:
        """Get recent alerts grouped by category"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        recent_alerts = [alert for alert in st.session_state.enterprise_alerts 
                        if alert['timestamp'] > cutoff_time]
        
        categories = {}
        for alert in recent_alerts:
            category = alert.get('category', 'other')
            if category not in categories:
                categories[category] = []
            categories[category].append(alert)
        
        return categories

# =================== Main Enterprise Application ===================
def main():
    st.title("🏢 Enterprise SQL Server AI Monitor")
    st.markdown("**Real-time monitoring, AI-powered analytics, and predictive maintenance for SQL Server infrastructure**")
    
    # Initialize session state
    if 'sql_connector' not in st.session_state:
        st.session_state.sql_connector = None
    
    if 'metrics_collector' not in st.session_state:
        st.session_state.metrics_collector = None
    
    if 'claude_analyzer' not in st.session_state:
        st.session_state.claude_analyzer = None
    
    if 'alert_manager' not in st.session_state:
        st.session_state.alert_manager = EnterpriseAlertManager()
    
    # Sidebar configuration
    with st.sidebar:
        st.header("🔧 Enterprise Configuration")
        
        # System Status
        st.subheader("📊 System Status")
        if not PYODBC_AVAILABLE:
            st.error("❌ pyodbc not available")
            st.info("💡 Install pyodbc for real SQL connections")
        else:
            st.success("✅ pyodbc available")
        
        if not ANTHROPIC_AVAILABLE:
            st.warning("⚠️ anthropic not available")
            st.info("💡 Install anthropic for AI features")
        else:
            st.success("✅ anthropic available")
        
        # Demo mode indicator
        if not PYODBC_AVAILABLE:
            st.markdown("""
            <div style="background: linear-gradient(135deg, #ff6b6b 0%, #ee5a52 100%); 
                        padding: 1rem; border-radius: 8px; color: white; margin: 1rem 0;">
                <strong>🎭 DEMO MODE</strong><br>
                Using simulated data. Install pyodbc + ODBC drivers for real connections.
            </div>
            """, unsafe_allow_html=True)
        
        st.markdown("---")
        
        # Claude AI Configuration
        st.subheader("🤖 Claude AI Settings")
        claude_api_key = st.text_input("Claude AI API Key", type="password", 
                                      value="", 
                                      help="Enter your Anthropic Claude API key")
        
        if claude_api_key:
            if 'claude_analyzer' not in st.session_state or st.session_state.claude_analyzer is None:
                st.session_state.claude_analyzer = ClaudeAIAnalyzer(claude_api_key)
            
            if st.session_state.claude_analyzer.enabled:
                st.success("✅ Claude AI Connected")
            else:
                st.error("❌ Claude AI Connection Failed")
        else:
            st.warning("⚠️ Claude AI not configured")
        
        st.markdown("---")
        
        # SQL Server Configuration
        st.subheader("🗄️ SQL Server Configuration")
        
        if PYODBC_AVAILABLE:
            # Configuration for 3 SQL Servers
            server_configs = []
            
            for i in range(1, 4):
                with st.expander(f"SQL Server {i} Configuration"):
                    server_name = st.text_input(f"Server {i} Name", value=f"SQL-Server-{i}", key=f"name_{i}")
                    server_ip = st.text_input(f"Server {i} IP/FQDN", value="", key=f"ip_{i}")
                    server_port = st.text_input(f"Server {i} Port", value="1433", key=f"port_{i}")
                    database = st.text_input(f"Database", value="master", key=f"db_{i}")
                    username = st.text_input(f"Username", value="sa", key=f"user_{i}")
                    password = st.text_input(f"Password", type="password", value="", key=f"pass_{i}")
                    
                    if server_ip and password:
                        server_configs.append({
                            'name': server_name,
                            'server': f"{server_ip},{server_port}",
                            'database': database,
                            'username': username,
                            'password': password
                        })
            
            # Initialize SQL connector if configurations are provided
            if server_configs and len(server_configs) > 0:
                if st.button("🔌 Test Connections"):
                    st.session_state.sql_connector = SQLServerConnector(server_configs)
                    st.session_state.metrics_collector = SQLServerMetricsCollector(st.session_state.sql_connector)
                    
                    # Test all connections
                    for config in server_configs:
                        if st.session_state.sql_connector.test_connection(config):
                            st.success(f"✅ {config['name']} connected")
                        else:
                            st.error(f"❌ {config['name']} failed")
                
                if st.session_state.sql_connector is None:
                    st.session_state.sql_connector = SQLServerConnector(server_configs)
                    st.session_state.metrics_collector = SQLServerMetricsCollector(st.session_state.sql_connector)
        else:
            st.info("📝 **Demo Mode Configuration**")
            st.write("Using 3 simulated SQL Server instances:")
            st.write("• SQL-Server-1 (Demo)")
            st.write("• SQL-Server-2 (Demo)")
            st.write("• SQL-Server-3 (Demo)")
            st.write("")
            st.write("Install pyodbc + ODBC drivers for real connections.")
        
        st.markdown("---")
        
        # Monitoring settings
        st.subheader("📊 Monitoring Settings")
        refresh_interval = st.slider("Refresh Interval (seconds)", 10, 300, 60)
        enable_ai_analysis = st.checkbox("Enable AI Analysis", value=True)
        enable_predictive_alerts = st.checkbox("Enable Predictive Alerts", value=True)
        
        st.markdown("---")
        
        # Connection status
        st.subheader("🔗 Connection Status")
        if st.session_state.sql_connector:
            if st.session_state.sql_connector.demo_mode:
                st.warning("🎭 Demo Mode Active")
                st.info("Simulated SQL Server data")
            else:
                st.success("✅ SQL Connectors Ready")
        else:
            if PYODBC_AVAILABLE:
                st.warning("⚠️ Configure SQL Servers")
            else:
                st.error("❌ Install pyodbc first")
        
        if st.session_state.claude_analyzer and st.session_state.claude_analyzer.enabled:
            st.success("✅ Claude AI Ready")
        else:
            if ANTHROPIC_AVAILABLE:
                st.warning("⚠️ Configure Claude AI")
            else:
                st.error("❌ Install anthropic package")
    
    # Check if systems are configured
    if not PYODBC_AVAILABLE:
        st.error("🚫 SQL Server connectivity not available")
        
        with st.expander("📋 Installation Instructions", expanded=True):
            st.markdown("""
            ### 🔧 Install SQL Server Connectivity
            
            **Windows:**
            ```bash
            pip install pyodbc
            ```
            Then download and install [Microsoft ODBC Driver 18](https://docs.microsoft.com/en-us/sql/connect/odbc/download-odbc-driver-for-sql-server)
            
            **Linux (Ubuntu/Debian):**
            ```bash
            # Install Microsoft ODBC Driver
            curl https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
            curl https://packages.microsoft.com/config/ubuntu/20.04/prod.list | sudo tee /etc/apt/sources.list.d/mssql-release.list
            sudo apt-get update
            sudo ACCEPT_EULA=Y apt-get install -y msodbcsql18
            
            # Install Python package
            pip install pyodbc
            ```
            
            **macOS:**
            ```bash
            # Install Microsoft ODBC Driver
            brew tap microsoft/mssql-release https://github.com/Microsoft/homebrew-mssql-release
            HOMEBREW_NO_ENV_FILTERING=1 ACCEPT_EULA=Y brew install msodbcsql18
            
            # Install Python package
            pip install pyodbc
            ```
            
            ### 🤖 Enable AI Features
            ```bash
            pip install anthropic
            ```
            Then add your [Anthropic API key](https://console.anthropic.com/) in the sidebar.
            """)
        
        st.info("🎭 **Currently running in DEMO MODE** with simulated data. Install dependencies above for real SQL Server monitoring.")
        
        # Continue with demo mode
        if not st.session_state.sql_connector:
            # Create demo configuration
            demo_configs = [
                {'name': 'SQL-Server-1', 'server': 'demo-server-1,1433', 'database': 'master', 'username': 'demo', 'password': 'demo'},
                {'name': 'SQL-Server-2', 'server': 'demo-server-2,1433', 'database': 'master', 'username': 'demo', 'password': 'demo'},
                {'name': 'SQL-Server-3', 'server': 'demo-server-3,1433', 'database': 'master', 'username': 'demo', 'password': 'demo'}
            ]
            st.session_state.sql_connector = SQLServerConnector(demo_configs)
            st.session_state.metrics_collector = SQLServerMetricsCollector(st.session_state.sql_connector)
    
    elif not st.session_state.sql_connector:
        st.error("🚫 Please configure SQL Server connections in the sidebar")
        st.info("👈 Use the sidebar to configure your 3 SQL Server instances")
        return
    
    # Main tabs
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "🏠 Dashboard", 
        "🤖 AI Insights", 
        "🚨 Alerts", 
        "📊 Performance",
        "🔧 Maintenance",
        "📈 Analytics"
    ])
    
    # Collect metrics from all servers
    all_server_metrics = {}
    all_health_summaries = {}
    
    for config in st.session_state.sql_connector.server_configs:
        server_name = config['name']
        
        # Collect metrics
        server_metrics = st.session_state.metrics_collector.collect_all_metrics(server_name)
        all_server_metrics[server_name] = server_metrics
        
        # Get health summary
        health_summary = st.session_state.metrics_collector.get_health_summary(server_name)
        all_health_summaries[server_name] = health_summary
        
        # Evaluate alerts
        alerts = st.session_state.alert_manager.evaluate_sql_server_alerts(
            server_name, server_metrics, health_summary
        )
        if alerts:
            st.session_state.alert_manager.add_alerts(alerts)
    
    # =================== Dashboard Tab ===================
    with tab1:
        st.header("🏢 Enterprise SQL Server Dashboard")
        
        # Overall cluster status
        st.subheader("🌐 Cluster Overview")
        
        online_servers = sum(1 for h in all_health_summaries.values() if h.get('status') == 'online')
        total_servers = len(all_health_summaries)
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Online Servers", f"{online_servers}/{total_servers}", 
                     delta="All systems operational" if online_servers == total_servers else "Issues detected")
        
        with col2:
            total_databases = sum(h.get('online_databases', 0) for h in all_health_summaries.values() if h.get('status') == 'online')
            st.metric("Total Databases", total_databases)
        
        with col3:
            total_sessions = sum(h.get('user_sessions', 0) for h in all_health_summaries.values() if h.get('status') == 'online')
            st.metric("Active Sessions", total_sessions)
        
        with col4:
            recent_alerts = len(st.session_state.alert_manager.get_alerts_by_category(1))
            alert_color = "🔴" if recent_alerts > 5 else "🟡" if recent_alerts > 0 else "🟢"
            st.metric(f"Alerts (1h) {alert_color}", recent_alerts)
        
        st.markdown("---")
        
        # Individual server status
        for server_name, health in all_health_summaries.items():
            if health.get('status') == 'online':
                st.markdown(f'<div class="server-status-online">🟢 <strong>{server_name}</strong> - Online</div>', 
                           unsafe_allow_html=True)
                
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    st.write(f"**Version:** {health.get('product_version', 'Unknown')[:10]}")
                
                with col2:
                    st.write(f"**Edition:** {health.get('edition', 'Unknown')[:20]}")
                
                with col3:
                    st.write(f"**Databases:** {health.get('online_databases', 0)}")
                
                with col4:
                    st.write(f"**Sessions:** {health.get('user_sessions', 0)}")
                
                # Server metrics
                if server_name in all_server_metrics:
                    metrics = all_server_metrics[server_name]
                    
                    # Performance metrics display
                    if 'system_metrics' in metrics and not metrics['system_metrics'].empty:
                        sys_metrics = metrics['system_metrics'].iloc[0]
                        
                        col1, col2, col3 = st.columns(3)
                        
                        with col1:
                            buffer_cache = sys_metrics.get('buffer_cache_hit_ratio', 0)
                            color = "🟢" if buffer_cache > 95 else "🟡" if buffer_cache > 90 else "🔴"
                            st.metric(f"Buffer Cache {color}", f"{buffer_cache:.1f}%")
                        
                        with col2:
                            page_life = sys_metrics.get('page_life_expectancy', 0)
                            color = "🟢" if page_life > 1000 else "🟡" if page_life > 300 else "🔴"
                            st.metric(f"Page Life Exp {color}", f"{page_life:.0f}s")
                        
                        with col3:
                            if 'active_connections' in metrics and not metrics['active_connections'].empty:
                                conn_metrics = metrics['active_connections'].iloc[0]
                                total_conn = conn_metrics.get('total_connections', 0)
                                color = "🟢" if total_conn < 100 else "🟡" if total_conn < 200 else "🔴"
                                st.metric(f"Connections {color}", total_conn)
                    
                    # Wait statistics
                    if 'wait_stats' in metrics and not metrics['wait_stats'].empty:
                        st.write("**Top Wait Statistics:**")
                        wait_stats = metrics['wait_stats'].head(3)
                        for _, wait in wait_stats.iterrows():
                            st.write(f"• {wait.get('wait_type', 'Unknown')}: {wait.get('wait_time_ms', 0):,.0f}ms")
                    
                    # Blocking sessions
                    if 'blocking_sessions' in metrics and not metrics['blocking_sessions'].empty:
                        blocking_count = len(metrics['blocking_sessions'])
                        st.warning(f"⚠️ {blocking_count} blocking sessions detected")
                    
            else:
                st.markdown(f'<div class="server-status-offline">🔴 <strong>{server_name}</strong> - Offline</div>', 
                           unsafe_allow_html=True)
                st.error(f"Error: {health.get('error', 'Unknown error')}")
            
            st.markdown("---")
    
    # =================== AI Insights Tab ===================
    with tab2:
        st.header("🤖 Claude AI Insights")
        
        if st.session_state.claude_analyzer and st.session_state.claude_analyzer.enabled:
            
            if st.button("🔍 Generate AI Analysis", type="primary"):
                with st.spinner("Claude AI is analyzing your SQL Server infrastructure..."):
                    
                    # Performance analysis
                    analysis = st.session_state.claude_analyzer.analyze_performance_metrics(all_server_metrics)
                    
                    st.markdown('<div class="claude-insight">', unsafe_allow_html=True)
                    st.subheader("📊 Performance Analysis")
                    st.write(analysis.get('overall_health', 'Analysis not available'))
                    st.markdown('</div>', unsafe_allow_html=True)
                    
                    # Critical issues
                    if analysis.get('critical_issues'):
                        st.markdown('<div class="alert-critical">', unsafe_allow_html=True)
                        st.subheader("🚨 Critical Issues")
                        st.write(analysis.get('critical_issues'))
                        st.markdown('</div>', unsafe_allow_html=True)
                    
                    # Recommendations
                    st.markdown('<div class="claude-insight">', unsafe_allow_html=True)
                    st.subheader("💡 AI Recommendations")
                    st.write(analysis.get('recommendations', 'No specific recommendations at this time'))
                    st.markdown('</div>', unsafe_allow_html=True)
            
            st.markdown("---")
            
            # Failure prediction
            st.subheader("🔮 Predictive Analysis")
            
            if st.button("🎯 Predict Potential Failures"):
                with st.spinner("Analyzing failure patterns..."):
                    predictions = st.session_state.claude_analyzer.predict_failures({}, all_server_metrics)
                    
                    st.markdown('<div class="claude-insight">', unsafe_allow_html=True)
                    st.write(predictions.get('predictions', 'Prediction analysis not available'))
                    st.markdown('</div>', unsafe_allow_html=True)
            
            st.markdown("---")
            
            # Maintenance planning
            st.subheader("🔧 Intelligent Maintenance Planning")
            
            if st.button("📋 Generate Maintenance Plan"):
                with st.spinner("Creating intelligent maintenance plan..."):
                    recent_alerts = st.session_state.alert_manager.get_alerts_by_category(24)
                    all_alerts = []
                    for category_alerts in recent_alerts.values():
                        all_alerts.extend(category_alerts)
                    
                    maintenance_plan = st.session_state.claude_analyzer.generate_maintenance_plan(
                        all_server_metrics, all_alerts
                    )
                    
                    st.markdown('<div class="claude-insight">', unsafe_allow_html=True)
                    st.write(maintenance_plan)
                    st.markdown('</div>', unsafe_allow_html=True)
        
        else:
            st.warning("🔧 Claude AI not configured. Please add your API key in the sidebar to enable AI-powered insights.")
            st.info("""
            **Claude AI Features:**
            - 🔍 Intelligent performance analysis
            - 🎯 Predictive failure detection
            - 💡 Automated recommendations
            - 📋 Smart maintenance planning
            - 🔮 Trend analysis and forecasting
            """)
    
    # =================== Alerts Tab ===================
    with tab3:
        st.header("🚨 Enterprise Alert Management")
        
        # Alert summary
        alert_categories = st.session_state.alert_manager.get_alerts_by_category(24)
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            critical_count = sum(len([a for a in alerts if a['severity'] == 'critical']) 
                               for alerts in alert_categories.values())
            st.metric("Critical Alerts (24h)", critical_count, delta="High Priority")
        
        with col2:
            warning_count = sum(len([a for a in alerts if a['severity'] == 'warning']) 
                              for alerts in alert_categories.values())
            st.metric("Warning Alerts (24h)", warning_count, delta="Monitor")
        
        with col3:
            total_alerts = sum(len(alerts) for alerts in alert_categories.values())
            st.metric("Total Alerts (24h)", total_alerts)
        
        with col4:
            categories_count = len(alert_categories)
            st.metric("Alert Categories", categories_count)
        
        st.markdown("---")
        
        # Alerts by category
        for category, alerts in alert_categories.items():
            if not alerts:
                continue
                
            st.subheader(f"📂 {category.title()} Alerts")
            
            for alert in sorted(alerts, key=lambda x: x['timestamp'], reverse=True)[:10]:
                timestamp_str = alert['timestamp'].strftime("%Y-%m-%d %H:%M:%S")
                
                if alert['severity'] == 'critical':
                    st.markdown(f"""
                    <div class="alert-critical">
                        <strong>🚨 CRITICAL</strong> - {alert['server']}<br>
                        <strong>Issue:</strong> {alert['message']}<br>
                        <strong>Time:</strong> {timestamp_str}<br>
                        <strong>Recommendation:</strong> {alert.get('recommendation', 'Immediate attention required')}
                    </div>
                    """, unsafe_allow_html=True)
                
                elif alert['severity'] == 'warning':
                    st.markdown(f"""
                    <div class="alert-warning">
                        <strong>⚠️ WARNING</strong> - {alert['server']}<br>
                        <strong>Issue:</strong> {alert['message']}<br>
                        <strong>Time:</strong> {timestamp_str}<br>
                        <strong>Recommendation:</strong> {alert.get('recommendation', 'Monitor closely')}
                    </div>
                    """, unsafe_allow_html=True)
            
            st.markdown("---")
        
        if not alert_categories:
            st.success("🎉 No alerts in the last 24 hours! All systems running smoothly.")
    
    # =================== Performance Tab ===================
    with tab4:
        st.header("📊 Performance Analytics")
        
        # Server selector
        selected_server = st.selectbox("Select Server for Detailed Analysis", 
                                      list(all_server_metrics.keys()))
        
        if selected_server and selected_server in all_server_metrics:
            server_metrics = all_server_metrics[selected_server]
            
            # CPU and Memory Analysis
            if 'cpu_utilization' in server_metrics and not server_metrics['cpu_utilization'].empty:
                st.subheader("💻 CPU Utilization Trends")
                
                cpu_data = server_metrics['cpu_utilization']
                
                fig = go.Figure()
                fig.add_trace(go.Scatter(
                    x=cpu_data['EventTime'],
                    y=cpu_data['SQLProcessUtilization'],
                    name='SQL Server CPU %',
                    line=dict(color='blue')
                ))
                fig.add_trace(go.Scatter(
                    x=cpu_data['EventTime'],
                    y=cpu_data['OtherProcessUtilization'],
                    name='Other Processes %',
                    line=dict(color='orange')
                ))
                
                fig.update_layout(
                    title=f"CPU Utilization - {selected_server}",
                    xaxis_title="Time",
                    yaxis_title="CPU Usage %",
                    height=400
                )
                
                st.plotly_chart(fig, use_container_width=True)
            
            # Memory analysis
            if 'memory_usage' in server_metrics and not server_metrics['memory_usage'].empty:
                st.subheader("🧠 Memory Analysis")
                
                memory_data = server_metrics['memory_usage'].iloc[0]
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.metric("Physical Memory (MB)", f"{memory_data.get('physical_memory_mb', 0):,.0f}")
                    st.metric("Committed Memory (MB)", f"{memory_data.get('committed_memory_mb', 0):,.0f}")
                
                with col2:
                    st.metric("Virtual Memory (MB)", f"{memory_data.get('virtual_memory_mb', 0):,.0f}")
                    st.metric("Target Memory (MB)", f"{memory_data.get('committed_target_mb', 0):,.0f}")
            
            # Wait statistics analysis
            if 'wait_stats' in server_metrics and not server_metrics['wait_stats'].empty:
                st.subheader("⏱️ Wait Statistics Analysis")
                
                wait_stats = server_metrics['wait_stats'].head(10)
                
                fig = px.bar(
                    wait_stats,
                    x='wait_type',
                    y='wait_time_ms',
                    title=f"Top Wait Types - {selected_server}",
                    labels={'wait_time_ms': 'Wait Time (ms)', 'wait_type': 'Wait Type'}
                )
                
                fig.update_xaxes(tickangle=45)
                st.plotly_chart(fig, use_container_width=True)
            
            # Disk I/O analysis
            if 'disk_io' in server_metrics and not server_metrics['disk_io'].empty:
                st.subheader("💾 Disk I/O Performance")
                
                disk_io = server_metrics['disk_io']
                
                col1, col2 = st.columns(2)
                
                with col1:
                    fig = px.bar(
                        disk_io.head(10),
                        x='database_name',
                        y='mb_read',
                        title="Data Read by Database (MB)"
                    )
                    fig.update_xaxes(tickangle=45)
                    st.plotly_chart(fig, use_container_width=True)
                
                with col2:
                    fig = px.bar(
                        disk_io.head(10),
                        x='database_name',
                        y='mb_written',
                        title="Data Written by Database (MB)"
                    )
                    fig.update_xaxes(tickangle=45)
                    st.plotly_chart(fig, use_container_width=True)
            
            # Index fragmentation
            if 'index_fragmentation' in server_metrics and not server_metrics['index_fragmentation'].empty:
                st.subheader("🔧 Index Fragmentation Analysis")
                
                frag_data = server_metrics['index_fragmentation']
                
                if not frag_data.empty:
                    fig = px.scatter(
                        frag_data,
                        x='page_count',
                        y='avg_fragmentation_in_percent',
                        hover_data=['schema_name', 'object_name', 'index_name'],
                        title="Index Fragmentation vs Page Count",
                        labels={
                            'page_count': 'Page Count',
                            'avg_fragmentation_in_percent': 'Fragmentation %'
                        }
                    )
                    
                    fig.add_hline(y=30, line_dash="dash", line_color="orange", 
                                 annotation_text="Fragmentation Threshold (30%)")
                    
                    st.plotly_chart(fig, use_container_width=True)
                    
                    st.write("**Most Fragmented Indexes:**")
                    for _, idx in frag_data.head(5).iterrows():
                        st.write(f"• {idx['schema_name']}.{idx['object_name']}.{idx['index_name']}: "
                               f"{idx['avg_fragmentation_in_percent']:.1f}% fragmented")
                else:
                    st.success("✅ No highly fragmented indexes detected")
    
    # =================== Maintenance Tab ===================
    with tab5:
        st.header("🔧 Proactive Maintenance Management")
        
        # Backup status overview
        st.subheader("💾 Backup Compliance Dashboard")
        
        backup_summary = []
        for server_name, metrics in all_server_metrics.items():
            if 'backup_status' in metrics and not metrics['backup_status'].empty:
                backup_data = metrics['backup_status']
                
                for _, backup in backup_data.iterrows():
                    db_name = backup.get('database_name')
                    last_full = backup.get('last_full_backup')
                    last_log = backup.get('last_log_backup')
                    
                    if last_full and last_full != '1900-01-01':
                        hours_since_full = (datetime.now() - pd.to_datetime(last_full)).total_seconds() / 3600
                    else:
                        hours_since_full = 999
                    
                    backup_summary.append({
                        'Server': server_name,
                        'Database': db_name,
                        'Hours Since Full Backup': hours_since_full,
                        'Last Full Backup': last_full,
                        'Recovery Model': backup.get('recovery_model_desc', 'Unknown')
                    })
        
        if backup_summary:
            backup_df = pd.DataFrame(backup_summary)
            
            # Color-code based on backup age
            def backup_status_color(hours):
                if hours < 24:
                    return "🟢"
                elif hours < 48:
                    return "🟡"
                else:
                    return "🔴"
            
            backup_df['Status'] = backup_df['Hours Since Full Backup'].apply(backup_status_color)
            
            st.dataframe(backup_df[['Server', 'Database', 'Status', 'Hours Since Full Backup', 'Recovery Model']], 
                        use_container_width=True)
        
        st.markdown("---")
        
        # Maintenance recommendations
        st.subheader("📋 Maintenance Recommendations")
        
        maintenance_tasks = []
        
        for server_name, metrics in all_server_metrics.items():
            # Index maintenance needs
            if 'index_fragmentation' in metrics and not metrics['index_fragmentation'].empty:
                frag_count = len(metrics['index_fragmentation'])
                if frag_count > 0:
                    maintenance_tasks.append({
                        'Server': server_name,
                        'Priority': 'High',
                        'Task': 'Index Maintenance',
                        'Description': f'{frag_count} indexes require attention (>30% fragmentation)',
                        'Estimated Time': '2-4 hours',
                        'Impact': 'Medium'
                    })
            
            # Buffer cache optimization
            if 'system_metrics' in metrics and not metrics['system_metrics'].empty:
                sys_metrics = metrics['system_metrics'].iloc[0]
                buffer_cache = sys_metrics.get('buffer_cache_hit_ratio', 100)
                
                if buffer_cache < 95:
                    maintenance_tasks.append({
                        'Server': server_name,
                        'Priority': 'Medium',
                        'Task': 'Buffer Cache Optimization',
                        'Description': f'Buffer cache hit ratio is {buffer_cache:.1f}%',
                        'Estimated Time': '1-2 hours',
                        'Impact': 'Low'
                    })
            
            # Weekly maintenance
            maintenance_tasks.append({
                'Server': server_name,
                'Priority': 'Low',
                'Task': 'Statistics Update',
                'Description': 'Update table statistics for query optimization',
                'Estimated Time': '30-60 minutes',
                'Impact': 'Low'
            })
        
        # Display maintenance tasks
        if maintenance_tasks:
            for task in maintenance_tasks:
                priority_color = {
                    'High': '🔴',
                    'Medium': '🟡', 
                    'Low': '🟢'
                }[task['Priority']]
                
                with st.expander(f"{priority_color} {task['Priority']} - {task['Task']} ({task['Server']})"):
                    col1, col2, col3, col4 = st.columns(4)
                    
                    with col1:
                        st.write(f"**Priority:** {task['Priority']}")
                    
                    with col2:
                        st.write(f"**Estimated Time:** {task['Estimated Time']}")
                    
                    with col3:
                        st.write(f"**Impact:** {task['Impact']}")
                    
                    with col4:
                        if st.button("Schedule", key=f"schedule_{task['Server']}_{task['Task']}"):
                            st.success(f"✅ Scheduled: {task['Task']} for {task['Server']}")
                    
                    st.write(f"**Description:** {task['Description']}")
        
        st.markdown("---")
        
        # Database integrity checks
        st.subheader("🔍 Database Integrity Monitoring")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Recommended DBCC Commands:**")
            st.code("""
-- Check database integrity
DBCC CHECKDB('YourDatabase') WITH NO_INFOMSGS;

-- Check allocation consistency
DBCC CHECKALLOC('YourDatabase');

-- Update statistics
UPDATE STATISTICS YourTable;

-- Rebuild indexes
ALTER INDEX ALL ON YourTable REBUILD;
            """, language="sql")
        
        with col2:
            st.write("**Automated Maintenance Scripts:**")
            if st.button("📥 Download Maintenance Scripts"):
                st.info("Maintenance scripts would be generated and downloaded here")
            
            st.write("**Maintenance Schedule:**")
            st.write("• Daily: Transaction log backups")
            st.write("• Weekly: Full database backups")
            st.write("• Weekly: Index maintenance")
            st.write("• Monthly: Statistics updates")
            st.write("• Quarterly: DBCC CHECKDB")
    
    # =================== Analytics Tab ===================
    with tab6:
        st.header("📈 Historical Analytics & Trends")
        
        st.subheader("📊 Performance Trends Analysis")
        
        # This would typically show historical data analysis
        # For now, showing current snapshot analysis
        
        # Performance metrics summary across all servers
        performance_summary = []
        
        for server_name, metrics in all_server_metrics.items():
            server_health = all_health_summaries.get(server_name, {})
            
            if server_health.get('status') == 'online':
                summary = {
                    'Server': server_name,
                    'Status': '🟢 Online',
                    'Databases': server_health.get('online_databases', 0),
                    'Sessions': server_health.get('user_sessions', 0)
                }
                
                # Add performance metrics
                if 'system_metrics' in metrics and not metrics['system_metrics'].empty:
                    sys_metrics = metrics['system_metrics'].iloc[0]
                    summary['Buffer Cache Hit %'] = sys_metrics.get('buffer_cache_hit_ratio', 0)
                    summary['Page Life Expectancy'] = sys_metrics.get('page_life_expectancy', 0)
                
                if 'active_connections' in metrics and not metrics['active_connections'].empty:
                    conn_metrics = metrics['active_connections'].iloc[0]
                    summary['Total Connections'] = conn_metrics.get('total_connections', 0)
                    summary['Running Sessions'] = conn_metrics.get('running_sessions', 0)
                
                performance_summary.append(summary)
            else:
                performance_summary.append({
                    'Server': server_name,
                    'Status': '🔴 Offline',
                    'Databases': 0,
                    'Sessions': 0,
                    'Buffer Cache Hit %': 0,
                    'Page Life Expectancy': 0,
                    'Total Connections': 0,
                    'Running Sessions': 0
                })
        
        if performance_summary:
            performance_df = pd.DataFrame(performance_summary)
            st.dataframe(performance_df, use_container_width=True)
            
            # Performance comparison charts
            st.subheader("📊 Performance Comparison")
            
            online_servers = performance_df[performance_df['Status'] == '🟢 Online']
            
            if not online_servers.empty:
                col1, col2 = st.columns(2)
                
                with col1:
                    fig = px.bar(
                        online_servers,
                        x='Server',
                        y='Buffer Cache Hit %',
                        title="Buffer Cache Hit Ratio Comparison",
                        color='Buffer Cache Hit %',
                        color_continuous_scale='RdYlGn'
                    )
                    fig.add_hline(y=95, line_dash="dash", line_color="orange", 
                                 annotation_text="Target: 95%")
                    st.plotly_chart(fig, use_container_width=True)
                
                with col2:
                    fig = px.bar(
                        online_servers,
                        x='Server',
                        y='Total Connections',
                        title="Connection Count Comparison",
                        color='Total Connections',
                        color_continuous_scale='Blues'
                    )
                    st.plotly_chart(fig, use_container_width=True)
        
        # Alert trends
        st.subheader("🚨 Alert Trends")
        
        alert_categories = st.session_state.alert_manager.get_alerts_by_category(168)  # Last week
        
        if alert_categories:
            # Create alert trend data
            alert_trend_data = []
            
            for category, alerts in alert_categories.items():
                for alert in alerts:
                    alert_trend_data.append({
                        'Date': alert['timestamp'].date(),
                        'Hour': alert['timestamp'].hour,
                        'Category': category,
                        'Severity': alert['severity'],
                        'Server': alert['server']
                    })
            
            if alert_trend_data:
                alert_df = pd.DataFrame(alert_trend_data)
                
                # Daily alert counts
                daily_alerts = alert_df.groupby(['Date', 'Severity']).size().reset_index(name='Count')
                
                fig = px.line(
                    daily_alerts,
                    x='Date',
                    y='Count',
                    color='Severity',
                    title="Daily Alert Trends",
                    color_discrete_map={'critical': 'red', 'warning': 'orange', 'info': 'blue'}
                )
                
                st.plotly_chart(fig, use_container_width=True)
        else:
            st.success("📈 No significant alert trends detected - systems running smoothly!")
    
    # Auto-refresh functionality
    if 'last_refresh' not in st.session_state:
        st.session_state.last_refresh = datetime.now()
    
    time_since_refresh = (datetime.now() - st.session_state.last_refresh).seconds
    
    if time_since_refresh >= refresh_interval:
        st.session_state.last_refresh = datetime.now()
        st.rerun()
    
    # Status bar
    st.sidebar.markdown("---")
    st.sidebar.write(f"🔄 Last refresh: {st.session_state.last_refresh.strftime('%H:%M:%S')}")
    st.sidebar.write(f"⏱️ Next refresh: {refresh_interval - time_since_refresh}s")
    
    if st.sidebar.button("🔄 Refresh Now", type="primary"):
        st.rerun()

if __name__ == "__main__":
    main()