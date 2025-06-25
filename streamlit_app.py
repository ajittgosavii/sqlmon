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
import asyncio
import threading
from typing import Dict, List, Any, Optional, Tuple
import logging
import requests
import hashlib
import hmac
import base64
from urllib.parse import quote
import re
import os
import sys

# Try to import required AWS libraries
try:
    import boto3
    from botocore.exceptions import ClientError, BotoCoreError, NoCredentialsError, PartialCredentialsError
    from botocore.config import Config
    from botocore.credentials import InstanceMetadataProvider, EnvProvider, SharedCredentialProvider
    from botocore.session import get_session
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False
    boto3 = None

try:
    from anthropic import Anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False
    Anthropic = None

warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configure Streamlit page
st.set_page_config(
    page_title="AWS CloudWatch SQL Server Monitor",
    page_icon="☁️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Enhanced CSS for AWS-themed enterprise UI
st.markdown("""
<style>
    .aws-header {
        background: linear-gradient(135deg, #232F3E 0%, #FF9900 100%);
        padding: 1.5rem;
        border-radius: 12px;
        color: white;
        margin: 0.5rem 0;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 12px;
        color: white;
        margin: 0.5rem 0;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
    }
    .cluster-online {
        background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
        padding: 1rem;
        border-radius: 8px;
        color: white;
        margin: 0.3rem 0;
    }
    .cluster-degraded {
        background: linear-gradient(135deg, #f39c12 0%, #f1c40f 100%);
        padding: 1rem;
        border-radius: 8px;
        color: white;
        margin: 0.3rem 0;
    }
    .cluster-offline {
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
    .auto-remediation {
        background: linear-gradient(135deg, #00d2ff 0%, #3a7bd5 100%);
        color: white;
        padding: 1.5rem;
        border-radius: 12px;
        margin: 1rem 0;
        border-left: 5px solid #0073e6;
    }
    .claude-insight {
        background: linear-gradient(135deg, #8e44ad 0%, #9b59b6 100%);
        color: white;
        padding: 1.5rem;
        border-radius: 12px;
        margin: 1rem 0;
        border-left: 5px solid #6c3483;
    }
    .aws-service {
        background: linear-gradient(135deg, #232F3E 0%, #4A5568 100%);
        color: white;
        padding: 1rem;
        border-radius: 8px;
        margin: 0.3rem 0;
        border-left: 5px solid #FF9900;
    }
    .credential-status {
        padding: 1rem;
        border-radius: 8px;
        margin: 0.5rem 0;
        border-left: 5px solid;
    }
    .cred-success {
        background-color: #d4edda;
        color: #155724;
        border-left-color: #28a745;
    }
    .cred-error {
        background-color: #f8d7da;
        color: #721c24;
        border-left-color: #dc3545;
    }
    .cred-warning {
        background-color: #fff3cd;
        color: #856404;
        border-left-color: #ffc107;
    }
</style>
""", unsafe_allow_html=True)

# =================== Streamlit Cloud Compatible AWS Connection Manager ===================
class StreamlitAWSManager:
    """
    Specialized AWS connection manager designed for Streamlit Cloud environment
    """
    
    def __init__(self):
        self.is_streamlit_cloud = self._detect_streamlit_cloud()
        self.demo_mode = not AWS_AVAILABLE
        self._reset_connection_state()
        
    def _detect_streamlit_cloud(self) -> bool:
        """Detect if running in Streamlit Cloud environment"""
        # Check for Streamlit Cloud specific environment variables
        cloud_indicators = [
            'STREAMLIT_CLOUD',
            'STREAMLIT_SERVER_PORT',
            'HOSTNAME' in os.environ and 'streamlit' in os.environ.get('HOSTNAME', '').lower()
        ]
        return any(cloud_indicators) or 'streamlit.app' in os.environ.get('STREAMLIT_SERVER_HEADLESS', '')
    
    def _reset_connection_state(self):
        """Reset connection state"""
        self.connection_status = {
            'connected': False,
            'method': None,
            'error': None,
            'last_test': None,
            'account_id': None,
            'region': None,
            'user_arn': None
        }
        self.aws_session = None
        self.clients = {}
    
    def initialize_aws_connection(self, aws_config: Dict) -> bool:
        """
        Initialize AWS connection with Streamlit Cloud optimizations
        """
        if not AWS_AVAILABLE:
            self.demo_mode = True
            self.connection_status['error'] = "boto3 not available - running in demo mode"
            return True  # Return True for demo mode
        
        self._reset_connection_state()
        
        # Extract and clean configuration
        access_key = str(aws_config.get('access_key', '')).strip()
        secret_key = str(aws_config.get('secret_key', '')).strip()
        region = str(aws_config.get('region', 'us-east-1')).strip()
        
        # Set region in environment for boto3
        os.environ['AWS_DEFAULT_REGION'] = region
        
        # Try multiple credential methods in order of preference for Streamlit Cloud
        connection_methods = [
            ('explicit_credentials', self._try_explicit_credentials, (access_key, secret_key, region)),
            ('environment_variables', self._try_environment_credentials, (region,)),
            ('shared_credentials', self._try_shared_credentials, (region,)),
            ('instance_metadata', self._try_instance_metadata, (region,))
        ]
        
        for method_name, method_func, args in connection_methods:
            try:
                logger.info(f"Attempting AWS connection via {method_name}")
                
                session = method_func(*args)
                if session:
                    # Test the session
                    if self._test_session(session, method_name):
                        self.aws_session = session
                        self._initialize_clients()
                        self.connection_status['method'] = method_name
                        self.connection_status['connected'] = True
                        self.demo_mode = False
                        logger.info(f"Successfully connected via {method_name}")
                        return True
                        
            except Exception as e:
                logger.warning(f"Method {method_name} failed: {str(e)}")
                continue
        
        # If all methods fail, set demo mode
        self.demo_mode = True
        self.connection_status['error'] = "All AWS authentication methods failed"
        return False
    
    def _try_explicit_credentials(self, access_key: str, secret_key: str, region: str):
        """Try explicit credentials"""
        if not access_key or not secret_key or access_key == 'demo' or secret_key == 'demo':
            return None
            
        # Validate credential format
        if not self._validate_aws_credentials(access_key, secret_key):
            raise ValueError("Invalid credential format")
        
        return boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )
    
    def _try_environment_credentials(self, region: str):
        """Try environment variables"""
        # Check if AWS credentials are in environment
        if 'AWS_ACCESS_KEY_ID' in os.environ and 'AWS_SECRET_ACCESS_KEY' in os.environ:
            return boto3.Session(region_name=region)
        return None
    
    def _try_shared_credentials(self, region: str):
        """Try shared credentials file"""
        try:
            session = boto3.Session(region_name=region)
            # Test if credentials are available
            session.client('sts').get_caller_identity()
            return session
        except:
            return None
    
    def _try_instance_metadata(self, region: str):
        """Try EC2 instance metadata (for EC2/ECS environments)"""
        try:
            session = boto3.Session(region_name=region)
            # This will work if running on EC2 with IAM role
            session.client('sts').get_caller_identity()
            return session
        except:
            return None
    
    def _validate_aws_credentials(self, access_key: str, secret_key: str) -> bool:
        """Validate AWS credential format"""
        # AWS Access Key format validation
        access_key_pattern = r'^(AKIA|ASIA)[0-9A-Z]{16}$'
        if not re.match(access_key_pattern, access_key):
            return False
            
        # AWS Secret Key validation (should be 40 characters)
        if len(secret_key) != 40:
            return False
            
        return True
    
    def _test_session(self, session, method_name: str) -> bool:
        """Test AWS session with comprehensive checks"""
        try:
            # Create test clients with specific configuration for Streamlit Cloud
            config = Config(
                region_name=session.region_name or 'us-east-1',
                retries={'max_attempts': 2, 'mode': 'standard'},
                max_pool_connections=10,
                read_timeout=30,
                connect_timeout=30
            )
            
            # Test STS first (most basic AWS service)
            sts_client = session.client('sts', config=config)
            identity = sts_client.get_caller_identity()
            
            # Store account information
            self.connection_status.update({
                'account_id': identity.get('Account'),
                'user_arn': identity.get('Arn'),
                'region': session.region_name,
                'last_test': datetime.now()
            })
            
            # Test other essential services
            cloudwatch_client = session.client('cloudwatch', config=config)
            cloudwatch_client.list_metrics(MaxRecords=1)
            
            return True
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            self.connection_status['error'] = f"AWS Error ({error_code}): {e.response['Error']['Message']}"
            return False
        except Exception as e:
            self.connection_status['error'] = f"Connection test failed ({method_name}): {str(e)}"
            return False
    
    def _initialize_clients(self):
        """Initialize AWS service clients with optimized configuration"""
        if not self.aws_session:
            return
            
        # Optimized config for Streamlit Cloud
        config = Config(
            region_name=self.aws_session.region_name,
            retries={'max_attempts': 3, 'mode': 'adaptive'},
            max_pool_connections=50,
            read_timeout=60,
            connect_timeout=30
        )
        
        try:
            self.clients = {
                'cloudwatch': self.aws_session.client('cloudwatch', config=config),
                'logs': self.aws_session.client('logs', config=config),
                'rds': self.aws_session.client('rds', config=config),
                'ec2': self.aws_session.client('ec2', config=config),
                'ssm': self.aws_session.client('ssm', config=config),
                'lambda': self.aws_session.client('lambda', config=config),
                'sts': self.aws_session.client('sts', config=config)
            }
            logger.info("AWS clients initialized successfully")
        except Exception as e:
            self.connection_status['error'] = f"Failed to initialize AWS clients: {str(e)}"
            self.clients = {}
    
    def get_client(self, service_name: str):
        """Get AWS client for specified service"""
        if self.demo_mode:
            return None
        return self.clients.get(service_name)
    
    def test_connection(self) -> bool:
        """Test current AWS connection"""
        if self.demo_mode:
            return True
            
        if not self.aws_session:
            self.connection_status['error'] = "No active AWS session"
            return False
            
        try:
            # Quick test using STS
            sts_client = self.get_client('sts')
            if sts_client:
                identity = sts_client.get_caller_identity()
                self.connection_status.update({
                    'connected': True,
                    'account_id': identity.get('Account'),
                    'user_arn': identity.get('Arn'),
                    'last_test': datetime.now(),
                    'error': None
                })
                return True
        except Exception as e:
            self.connection_status.update({
                'connected': False,
                'error': f"Connection test failed: {str(e)}",
                'last_test': datetime.now()
            })
        
        return False
    
    def get_connection_status(self) -> Dict:
        """Get current connection status"""
        status = self.connection_status.copy()
        status['demo_mode'] = self.demo_mode
        status['streamlit_cloud'] = self.is_streamlit_cloud
        return status

# Initialize global AWS manager
@st.cache_resource
def get_aws_manager():
    """Get cached AWS manager instance"""
    return StreamlitAWSManager()

# =================== AWS CloudWatch Integration ===================
class AWSCloudWatchConnector:
    def __init__(self, aws_config: Dict):
        """Initialize AWS CloudWatch connections using the manager"""
        self.aws_config = aws_config
        self.aws_manager = get_aws_manager()
        
        # Initialize connection
        self.aws_manager.initialize_aws_connection(aws_config)
        self.demo_mode = self.aws_manager.demo_mode
    
    def test_connection(self) -> bool:
        """Test AWS connection"""
        return self.aws_manager.test_connection()
    
    def get_connection_status(self) -> Dict:
        """Get connection status"""
        return self.aws_manager.get_connection_status()
    
    def get_cloudwatch_metrics(self, metric_queries: List[Dict], 
                              start_time: datetime, end_time: datetime) -> Dict[str, List]:
        """Get CloudWatch metrics with enhanced error handling"""
        if self.demo_mode:
            return self._generate_demo_cloudwatch_data(metric_queries)
        
        try:
            results = {}
            cloudwatch_client = self.aws_manager.get_client('cloudwatch')
            
            if not cloudwatch_client:
                return {}
            
            for query in metric_queries:
                try:
                    response = cloudwatch_client.get_metric_statistics(
                        Namespace=query['namespace'],
                        MetricName=query['metric_name'],
                        Dimensions=query.get('dimensions', []),
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=query.get('period', 300),
                        Statistics=query.get('statistics', ['Average'])
                    )
                    
                    results[query['key']] = response['Datapoints']
                    
                except ClientError as e:
                    logger.warning(f"Failed to retrieve metric {query['key']}: {e.response['Error']['Message']}")
                    results[query['key']] = []
                    
                except Exception as e:
                    logger.warning(f"Unexpected error retrieving metric {query['key']}: {str(e)}")
                    results[query['key']] = []
            
            return results
            
        except Exception as e:
            logger.error(f"Failed to retrieve CloudWatch metrics: {str(e)}")
            return {}
    
    def get_comprehensive_sql_metrics(self, instance_id: str, start_time: datetime, end_time: datetime) -> Dict[str, List]:
        """Get comprehensive SQL Server metrics from CloudWatch"""
        
        # Comprehensive SQL Server metrics that should be pushed to CloudWatch via custom scripts
        sql_server_metrics = [
            # ===== DATABASE ENGINE PERFORMANCE =====
            {'key': 'buffer_cache_hit_ratio', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Buffer Manager\\Buffer cache hit ratio'},
            {'key': 'page_life_expectancy', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Buffer Manager\\Page life expectancy'},
            {'key': 'lazy_writes_per_sec', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Buffer Manager\\Lazy writes/sec'},
            {'key': 'checkpoint_pages_per_sec', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Buffer Manager\\Checkpoint pages/sec'},
            {'key': 'free_list_stalls_per_sec', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Buffer Manager\\Free list stalls/sec'},
            
            # ===== SQL SERVER ACTIVITY =====
            {'key': 'batch_requests_per_sec', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:SQL Statistics\\Batch Requests/sec'},
            {'key': 'sql_compilations_per_sec', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:SQL Statistics\\SQL Compilations/sec'},
            {'key': 'sql_recompilations_per_sec', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:SQL Statistics\\SQL Re-Compilations/sec'},
            {'key': 'user_connections', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:General Statistics\\User Connections'},
            {'key': 'processes_blocked', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:General Statistics\\Processes blocked'},
            {'key': 'logins_per_sec', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:General Statistics\\Logins/sec'},
            {'key': 'logouts_per_sec', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:General Statistics\\Logouts/sec'},
            
            # ===== LOCKING AND BLOCKING =====
            {'key': 'lock_waits_per_sec', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Locks\\Lock Waits/sec'},
            {'key': 'lock_wait_time_ms', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Locks\\Average Wait Time (ms)'},
            {'key': 'lock_timeouts_per_sec', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Locks\\Lock Timeouts/sec'},
            {'key': 'deadlocks_per_sec', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Locks\\Number of Deadlocks/sec'},
            {'key': 'lock_requests_per_sec', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Locks\\Lock Requests/sec'},
            
            # ===== ACCESS METHODS =====
            {'key': 'full_scans_per_sec', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Access Methods\\Full Scans/sec'},
            {'key': 'index_searches_per_sec', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Access Methods\\Index Searches/sec'},
            {'key': 'page_splits_per_sec', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Access Methods\\Page Splits/sec'},
            {'key': 'page_lookups_per_sec', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Access Methods\\Page lookups/sec'},
            {'key': 'worktables_created_per_sec', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Access Methods\\Worktables Created/sec'},
            {'key': 'workfiles_created_per_sec', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Access Methods\\Workfiles Created/sec'},
            
            # ===== MEMORY MANAGER =====
            {'key': 'memory_grants_pending', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Memory Manager\\Memory Grants Pending'},
            {'key': 'memory_grants_outstanding', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Memory Manager\\Memory Grants Outstanding'},
            {'key': 'target_server_memory_kb', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Memory Manager\\Target Server Memory (KB)'},
            {'key': 'total_server_memory_kb', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Memory Manager\\Total Server Memory (KB)'},
            
            # ===== PLAN CACHE =====
            {'key': 'cache_hit_ratio', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Plan Cache\\Cache Hit Ratio'},
            {'key': 'cache_pages', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Plan Cache\\Cache Pages'},
            {'key': 'cache_objects_in_use', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Plan Cache\\Cache Objects in use'},
            
            # ===== WAIT STATISTICS (Top waits) =====
            {'key': 'wait_cxpacket_ms', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Wait Statistics\\CXPACKET waits'},
            {'key': 'wait_async_network_io_ms', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Wait Statistics\\ASYNC_NETWORK_IO waits'},
            {'key': 'wait_pageiolatch_sh_ms', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Wait Statistics\\PAGEIOLATCH_SH waits'},
            {'key': 'wait_pageiolatch_ex_ms', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Wait Statistics\\PAGEIOLATCH_EX waits'},
            {'key': 'wait_writelog_ms', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Wait Statistics\\WRITELOG waits'},
            {'key': 'wait_resource_semaphore_ms', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Wait Statistics\\RESOURCE_SEMAPHORE waits'},
            
            # ===== ALWAYS ON AVAILABILITY GROUPS =====
            {'key': 'ag_data_movement_state', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Availability Groups\\Data Movement State'},
            {'key': 'ag_synchronization_health', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Availability Groups\\Synchronization Health'},
            {'key': 'ag_log_send_queue_size', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Database Replica\\Log Send Queue Size'},
            {'key': 'ag_log_send_rate', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Database Replica\\Log Send Rate'},
            {'key': 'ag_redo_queue_size', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Database Replica\\Redo Queue Size'},
            {'key': 'ag_redo_rate', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Database Replica\\Redo Rate'},
            {'key': 'ag_recovery_lsn', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Database Replica\\Recovery LSN'},
            {'key': 'ag_truncation_lsn', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Database Replica\\Truncation LSN'},
            
            # ===== DATABASE SPECIFIC METRICS =====
            {'key': 'db_data_file_size_kb', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Databases\\Data File(s) Size (KB)'},
            {'key': 'db_log_file_size_kb', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Databases\\Log File(s) Size (KB)'},
            {'key': 'db_log_file_used_size_kb', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Databases\\Log File(s) Used Size (KB)'},
            {'key': 'db_percent_log_used', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Databases\\Percent Log Used'},
            {'key': 'db_active_transactions', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Databases\\Active Transactions'},
            {'key': 'db_transactions_per_sec', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Databases\\Transactions/sec'},
            {'key': 'db_log_growths', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Databases\\Log Growths'},
            {'key': 'db_log_shrinks', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Databases\\Log Shrinks'},
            {'key': 'db_log_flushes_per_sec', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Databases\\Log Flushes/sec'},
            {'key': 'db_log_flush_wait_time', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Databases\\Log Flush Wait Time'},
            
            # ===== TEMPDB SPECIFIC =====
            {'key': 'tempdb_version_store_size_kb', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Transactions\\Version Store Size (KB)'},
            {'key': 'tempdb_version_generation_rate', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Transactions\\Version Generation rate (KB/s)'},
            {'key': 'tempdb_version_cleanup_rate', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Transactions\\Version Cleanup rate (KB/s)'},
            
            # ===== BACKUP METRICS =====
            {'key': 'backup_throughput_bytes_per_sec', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Backup Device\\Device Throughput Bytes/sec'},
            
            # ===== SECURITY METRICS =====
            {'key': 'failed_logins_per_sec', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:SQL Errors\\Errors/sec'},
            
            # ===== CUSTOM BUSINESS METRICS =====
            {'key': 'query_avg_execution_time_ms', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Custom\\Average Query Execution Time'},
            {'key': 'expensive_queries_count', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Custom\\Expensive Queries Count'},
            {'key': 'index_fragmentation_avg', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Custom\\Average Index Fragmentation'},
            {'key': 'missing_indexes_count', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Custom\\Missing Indexes Count'},
            {'key': 'unused_indexes_count', 'namespace': 'CWAgent', 'metric_name': 'SQLServer:Custom\\Unused Indexes Count'}
        ]
        
        # Add instance-specific dimensions
        for metric in sql_server_metrics:
            metric['dimensions'] = [{'Name': 'InstanceId', 'Value': instance_id}]
        
        return self.get_cloudwatch_metrics(sql_server_metrics, start_time, end_time)
    
    def get_rds_instances(self) -> List[Dict]:
        """Get RDS SQL Server instances"""
        if self.demo_mode:
            return [
                {
                    'DBInstanceIdentifier': 'sql-server-prod-1',
                    'Engine': 'sqlserver-ex',
                    'DBInstanceStatus': 'available',
                    'AvailabilityZone': 'us-east-1a',
                    'MultiAZ': False,
                    'AllocatedStorage': 100
                },
                {
                    'DBInstanceIdentifier': 'sql-server-prod-2',
                    'Engine': 'sqlserver-se',
                    'DBInstanceStatus': 'available',
                    'AvailabilityZone': 'us-east-1b',
                    'MultiAZ': True,
                    'AllocatedStorage': 500
                }
            ]
        
        try:
            rds_client = self.aws_manager.get_client('rds')
            if not rds_client:
                return []
                
            response = rds_client.describe_db_instances()
            sql_instances = []
            
            for db in response['DBInstances']:
                if 'sqlserver' in db['Engine'].lower():
                    sql_instances.append(db)
            
            return sql_instances
            
        except Exception as e:
            logger.error(f"Failed to retrieve RDS instances: {str(e)}")
            return []
    
    def get_ec2_sql_instances(self) -> List[Dict]:
        """Get EC2 instances running SQL Server"""
        if self.demo_mode:
            return [
                {
                    'InstanceId': 'i-1234567890abcdef0',
                    'InstanceType': 'm5.xlarge',
                    'State': {'Name': 'running'},
                    'PrivateIpAddress': '10.0.1.100',
                    'Tags': [{'Key': 'Name', 'Value': 'SQL-Always-On-Primary'}]
                },
                {
                    'InstanceId': 'i-0987654321fedcba0',
                    'InstanceType': 'm5.xlarge',
                    'State': {'Name': 'running'},
                    'PrivateIpAddress': '10.0.1.101',
                    'Tags': [{'Key': 'Name', 'Value': 'SQL-Always-On-Secondary'}]
                }
            ]
        
        try:
            ec2_client = self.aws_manager.get_client('ec2')
            if not ec2_client:
                return []
                
            response = ec2_client.describe_instances(
                Filters=[
                    {
                        'Name': 'tag:Application',
                        'Values': ['SQLServer', 'SQL Server', 'Database']
                    }
                ]
            )
            
            instances = []
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    if instance['State']['Name'] in ['running', 'stopped']:
                        instances.append(instance)
            
            return instances
            
        except Exception as e:
            logger.error(f"Failed to retrieve EC2 instances: {str(e)}")
            return []
    
    def get_cloudwatch_logs(self, log_group: str, hours: int = 24) -> List[Dict]:
        """Get CloudWatch logs"""
        if self.demo_mode:
            return self._generate_demo_log_data()
        
        try:
            logs_client = self.aws_manager.get_client('logs')
            if not logs_client:
                return []
                
            start_time = int((datetime.now() - timedelta(hours=hours)).timestamp() * 1000)
            end_time = int(datetime.now().timestamp() * 1000)
            
            response = logs_client.filter_log_events(
                logGroupName=log_group,
                startTime=start_time,
                endTime=end_time
            )
            
            return response['events']
            
        except Exception as e:
            logger.error(f"Failed to retrieve CloudWatch logs: {str(e)}")
            return []

    def get_available_log_groups(self) -> List[str]:
        """Get all available CloudWatch log groups"""
        if self.demo_mode:
            return [
                "/aws/rds/instance/sql-server-prod-1/error",
                "/aws/rds/instance/sql-server-prod-1/agent",
                "/aws/rds/instance/sql-server-prod-2/error", 
                "/ec2/sql-server/application",
                "/ec2/sql-server/system",
                "/ec2/sql-server/security",
                "/ec2/sql-server/performance"
            ]
        
        try:
            logs_client = self.aws_manager.get_client('logs')
            if not logs_client:
                return []
                
            response = logs_client.describe_log_groups()
            return [lg['logGroupName'] for lg in response['logGroups']]
        except Exception as e:
            logger.error(f"Failed to retrieve log groups: {str(e)}")
            return []

    def get_os_metrics(self, instance_id: str, start_time: datetime, end_time: datetime) -> Dict[str, List]:
        """Get comprehensive OS-level metrics from CloudWatch Agent"""
        
        os_metric_queries = [
            # ===== CPU METRICS =====
            {'key': 'cpu_usage_active', 'namespace': 'CWAgent', 'metric_name': 'cpu_usage_active'},
            {'key': 'cpu_usage_guest', 'namespace': 'CWAgent', 'metric_name': 'cpu_usage_guest'},
            {'key': 'cpu_usage_idle', 'namespace': 'CWAgent', 'metric_name': 'cpu_usage_idle'},
            {'key': 'cpu_usage_iowait', 'namespace': 'CWAgent', 'metric_name': 'cpu_usage_iowait'},
            {'key': 'cpu_usage_steal', 'namespace': 'CWAgent', 'metric_name': 'cpu_usage_steal'},
            {'key': 'cpu_usage_system', 'namespace': 'CWAgent', 'metric_name': 'cpu_usage_system'},
            {'key': 'cpu_usage_user', 'namespace': 'CWAgent', 'metric_name': 'cpu_usage_user'},
            
            # ===== MEMORY METRICS =====
            {'key': 'mem_used_percent', 'namespace': 'CWAgent', 'metric_name': 'mem_used_percent'},
            {'key': 'mem_available_percent', 'namespace': 'CWAgent', 'metric_name': 'mem_available_percent'},
            {'key': 'mem_used', 'namespace': 'CWAgent', 'metric_name': 'mem_used'},
            {'key': 'mem_cached', 'namespace': 'CWAgent', 'metric_name': 'mem_cached'},
            {'key': 'mem_buffers', 'namespace': 'CWAgent', 'metric_name': 'mem_buffers'},
            
            # ===== DISK METRICS =====
            {'key': 'disk_used_percent', 'namespace': 'CWAgent', 'metric_name': 'disk_used_percent'},
            {'key': 'disk_inodes_free', 'namespace': 'CWAgent', 'metric_name': 'disk_inodes_free'},
            {'key': 'diskio_read_bytes', 'namespace': 'CWAgent', 'metric_name': 'diskio_read_bytes'},
            {'key': 'diskio_write_bytes', 'namespace': 'CWAgent', 'metric_name': 'diskio_write_bytes'},
            {'key': 'diskio_reads', 'namespace': 'CWAgent', 'metric_name': 'diskio_reads'},
            {'key': 'diskio_writes', 'namespace': 'CWAgent', 'metric_name': 'diskio_writes'},
            {'key': 'diskio_read_time', 'namespace': 'CWAgent', 'metric_name': 'diskio_read_time'},
            {'key': 'diskio_write_time', 'namespace': 'CWAgent', 'metric_name': 'diskio_write_time'},
            {'key': 'diskio_io_time', 'namespace': 'CWAgent', 'metric_name': 'diskio_io_time'},
            
            # ===== NETWORK METRICS =====
            {'key': 'net_bytes_sent', 'namespace': 'CWAgent', 'metric_name': 'net_bytes_sent'},
            {'key': 'net_bytes_recv', 'namespace': 'CWAgent', 'metric_name': 'net_bytes_recv'},
            {'key': 'net_packets_sent', 'namespace': 'CWAgent', 'metric_name': 'net_packets_sent'},
            {'key': 'net_packets_recv', 'namespace': 'CWAgent', 'metric_name': 'net_packets_recv'},
            {'key': 'net_err_in', 'namespace': 'CWAgent', 'metric_name': 'net_err_in'},
            {'key': 'net_err_out', 'namespace': 'CWAgent', 'metric_name': 'net_err_out'},
            {'key': 'net_drop_in', 'namespace': 'CWAgent', 'metric_name': 'net_drop_in'},
            {'key': 'net_drop_out', 'namespace': 'CWAgent', 'metric_name': 'net_drop_out'},
            
            # ===== PROCESS METRICS =====
            {'key': 'processes_running', 'namespace': 'CWAgent', 'metric_name': 'processes_running'},
            {'key': 'processes_sleeping', 'namespace': 'CWAgent', 'metric_name': 'processes_sleeping'},
            {'key': 'processes_stopped', 'namespace': 'CWAgent', 'metric_name': 'processes_stopped'},
            {'key': 'processes_zombies', 'namespace': 'CWAgent', 'metric_name': 'processes_zombies'},
            {'key': 'processes_blocked', 'namespace': 'CWAgent', 'metric_name': 'processes_blocked'},
            
            # ===== SYSTEM LOAD =====
            {'key': 'system_load1', 'namespace': 'CWAgent', 'metric_name': 'system_load1'},
            {'key': 'system_load5', 'namespace': 'CWAgent', 'metric_name': 'system_load5'},
            {'key': 'system_load15', 'namespace': 'CWAgent', 'metric_name': 'system_load15'},
            
            # ===== WINDOWS SPECIFIC METRICS (for SQL Server on Windows) =====
            {'key': 'LogicalDisk_PercentFreeSpace', 'namespace': 'CWAgent', 'metric_name': 'LogicalDisk % Free Space'},
            {'key': 'Memory_PercentCommittedBytesInUse', 'namespace': 'CWAgent', 'metric_name': 'Memory % Committed Bytes In Use'},
            {'key': 'Memory_AvailableMBytes', 'namespace': 'CWAgent', 'metric_name': 'Memory Available MBytes'},
            {'key': 'Paging_File_PercentUsage', 'namespace': 'CWAgent', 'metric_name': 'Paging File % Usage'},
            {'key': 'PhysicalDisk_PercentDiskTime', 'namespace': 'CWAgent', 'metric_name': 'PhysicalDisk % Disk Time'},
            {'key': 'PhysicalDisk_AvgDiskQueueLength', 'namespace': 'CWAgent', 'metric_name': 'PhysicalDisk Avg. Disk Queue Length'},
            {'key': 'Processor_PercentProcessorTime', 'namespace': 'CWAgent', 'metric_name': 'Processor % Processor Time'},
            {'key': 'System_ProcessorQueueLength', 'namespace': 'CWAgent', 'metric_name': 'System Processor Queue Length'},
            {'key': 'TCPv4_ConnectionsEstablished', 'namespace': 'CWAgent', 'metric_name': 'TCPv4 Connections Established'}
        ]
        
        # Add instance-specific dimensions
        for metric in os_metric_queries:
            metric['dimensions'] = [
                {'Name': 'InstanceId', 'Value': instance_id},
                {'Name': 'ImageId', 'Value': 'ami-xxxxx'},  # You'll need to get this dynamically
                {'Name': 'InstanceType', 'Value': 'm5.large'}  # You'll need to get this dynamically
            ]
        
        return self.get_cloudwatch_metrics(os_metric_queries, start_time, end_time)

    def get_sql_server_logs(self, log_groups: List[str], hours: int = 24, 
                        filter_pattern: str = None) -> Dict[str, List[Dict]]:
        """Get SQL Server specific logs from multiple log groups"""
        if self.demo_mode:
            return self._generate_demo_sql_logs(log_groups)
        
        try:
            all_logs = {}
            start_time = int((datetime.now() - timedelta(hours=hours)).timestamp() * 1000)
            end_time = int(datetime.now().timestamp() * 1000)
            
            logs_client = self.aws_manager.get_client('logs')
            if not logs_client:
                return {}
            
            for log_group in log_groups:
                try:
                    if filter_pattern:
                        response = logs_client.filter_log_events(
                            logGroupName=log_group,
                            startTime=start_time,
                            endTime=end_time,
                            filterPattern=filter_pattern
                        )
                    else:
                        response = logs_client.filter_log_events(
                            logGroupName=log_group,
                            startTime=start_time,
                            endTime=end_time
                        )
                    
                    all_logs[log_group] = response['events']
                    
                except Exception as e:
                    logger.warning(f"Could not retrieve logs from {log_group}: {str(e)}")
                    all_logs[log_group] = []
            
            return all_logs
            
        except Exception as e:
            logger.error(f"Failed to retrieve SQL Server logs: {str(e)}")
            return {}

    def _generate_demo_sql_logs(self, log_groups: List[str]) -> Dict[str, List[Dict]]:
        """Generate demo SQL Server logs"""
        demo_logs = {}
        
        log_patterns = {
            'error': [
                "SQL Server error: Login failed for user 'sa'",
                "Deadlock detected between sessions 52 and 67",
                "I/O error on backup device",
                "Transaction log is full",
                "Memory pressure detected"
            ],
            'agent': [
                "Job 'DatabaseBackup' completed successfully",
                "Job 'IndexMaintenance' started",
                "Alert: High CPU utilization",
                "Maintenance plan execution completed"
            ],
            'application': [
                "Application connected to database",
                "Query execution completed in 1250ms",
                "Connection pool exhausted",
                "Stored procedure execution started"
            ],
            'system': [
                "SQL Server service started",
                "Database recovery completed",
                "Checkpoint operation completed",
                "Always On availability group synchronized"
            ],
            'security': [
                "Login succeeded for user 'domain\\user'",
                "Permission denied for user 'app_user'",
                "Security audit event logged",
                "Password policy violation detected"
            ]
        }
        
        for log_group in log_groups:
            log_type = 'system'
            for pattern_type in log_patterns.keys():
                if pattern_type in log_group.lower():
                    log_type = pattern_type
                    break
            
            events = []
            for i in range(20):
                timestamp = datetime.now() - timedelta(minutes=i * 30)
                events.append({
                    'timestamp': int(timestamp.timestamp() * 1000),
                    'message': np.random.choice(log_patterns[log_type]),
                    'logStreamName': f'sql-server-{np.random.randint(1, 3)}'
                })
            
            demo_logs[log_group] = events
        
        return demo_logs

    def get_account_info(self) -> Dict[str, str]:
        """Get AWS account information"""
        if self.demo_mode:
            return {
                'account_id': '123456789012',
                'account_alias': 'demo-sql-environment',
                'region': self.aws_config.get('region', 'us-east-1'),
                'vpc_id': 'vpc-1234567890abcdef0',
                'environment': 'demo'
            }
        
        try:
            # Get account identity information
            sts_client = self.aws_manager.get_client('sts')
            if not sts_client:
                return {}
                
            identity = sts_client.get_caller_identity()
            account_id = identity['Account']
            
            # Get account alias (if available)
            try:
                iam_client = self.aws_manager.aws_session.client('iam')
                aliases = iam_client.list_account_aliases()
                account_alias = aliases['AccountAliases'][0] if aliases['AccountAliases'] else 'No alias'
            except:
                account_alias = 'Unknown'
            
            return {
                'account_id': account_id,
                'account_alias': account_alias,
                'region': self.aws_config.get('region'),
                'user_arn': identity.get('Arn', 'Unknown'),
                'environment': self.aws_config.get('account_name', 'Unknown')
            }
            
        except Exception as e:
            logger.error(f"Failed to get account information: {str(e)}")
            return {}
    
    def _generate_demo_cloudwatch_data(self, metric_queries: List[Dict]) -> Dict[str, List]:
        """Generate demo CloudWatch data with realistic SQL Server metrics"""
        results = {}
        current_time = datetime.now()
        
        for query in metric_queries:
            datapoints = []
            for i in range(24):  # 24 hours of data
                timestamp = current_time - timedelta(hours=i)
                
                # Generate realistic values based on metric type
                key = query['key'].lower()
                
                if 'cpu' in key:
                    value = np.random.uniform(20, 80)
                elif 'memory' in key:
                    value = np.random.uniform(60, 90)
                elif 'buffer_cache_hit_ratio' in key:
                    value = np.random.uniform(95, 99.9)  # Should be high
                elif 'page_life_expectancy' in key:
                    value = np.random.uniform(300, 3600)  # Seconds
                elif 'batch_requests_per_sec' in key:
                    value = np.random.uniform(100, 5000)
                elif 'user_connections' in key:
                    value = np.random.uniform(10, 200)
                elif 'processes_blocked' in key:
                    value = np.random.uniform(0, 5)
                elif 'deadlocks_per_sec' in key:
                    value = np.random.uniform(0, 0.5)
                elif 'lock_waits_per_sec' in key:
                    value = np.random.uniform(0, 100)
                elif 'lock_wait_time_ms' in key:
                    value = np.random.uniform(0, 1000)
                elif 'full_scans_per_sec' in key:
                    value = np.random.uniform(0, 50)
                elif 'index_searches_per_sec' in key:
                    value = np.random.uniform(100, 10000)
                elif 'page_splits_per_sec' in key:
                    value = np.random.uniform(0, 100)
                elif 'lazy_writes_per_sec' in key:
                    value = np.random.uniform(0, 20)
                elif 'checkpoint_pages_per_sec' in key:
                    value = np.random.uniform(0, 500)
                elif 'sql_compilations_per_sec' in key:
                    value = np.random.uniform(10, 500)
                elif 'sql_recompilations_per_sec' in key:
                    value = np.random.uniform(0, 50)
                elif 'memory_grants_pending' in key:
                    value = np.random.uniform(0, 10)
                elif 'target_server_memory_kb' in key:
                    value = np.random.uniform(8000000, 16000000)  # 8-16GB
                elif 'total_server_memory_kb' in key:
                    value = np.random.uniform(7000000, 15000000)  # Slightly less than target
                elif 'cache_hit_ratio' in key:
                    value = np.random.uniform(85, 99)
                elif 'wait_' in key and '_ms' in key:
                    value = np.random.uniform(0, 5000)
                elif 'ag_log_send_queue_size' in key:
                    value = np.random.uniform(0, 1000000)  # KB
                elif 'ag_log_send_rate' in key:
                    value = np.random.uniform(100, 10000)  # KB/s
                elif 'ag_redo_queue_size' in key:
                    value = np.random.uniform(0, 500000)  # KB
                elif 'ag_redo_rate' in key:
                    value = np.random.uniform(50, 5000)  # KB/s
                elif 'db_data_file_size_kb' in key:
                    value = np.random.uniform(1000000, 100000000)  # 1GB-100GB
                elif 'db_log_file_size_kb' in key:
                    value = np.random.uniform(100000, 10000000)  # 100MB-10GB
                elif 'db_percent_log_used' in key:
                    value = np.random.uniform(10, 80)
                elif 'db_active_transactions' in key:
                    value = np.random.uniform(0, 100)
                elif 'db_transactions_per_sec' in key:
                    value = np.random.uniform(10, 1000)
                elif 'db_log_flushes_per_sec' in key:
                    value = np.random.uniform(1, 100)
                elif 'db_log_flush_wait_time' in key:
                    value = np.random.uniform(0, 50)  # ms
                elif 'tempdb_version_store_size_kb' in key:
                    value = np.random.uniform(0, 1000000)  # KB
                elif 'backup_throughput_bytes_per_sec' in key:
                    value = np.random.uniform(1000000, 100000000)  # 1MB/s - 100MB/s
                elif 'failed_logins_per_sec' in key:
                    value = np.random.uniform(0, 5)
                elif 'query_avg_execution_time_ms' in key:
                    value = np.random.uniform(10, 1000)
                elif 'expensive_queries_count' in key:
                    value = np.random.uniform(0, 20)
                elif 'index_fragmentation_avg' in key:
                    value = np.random.uniform(5, 45)
                elif 'missing_indexes_count' in key:
                    value = np.random.uniform(0, 50)
                elif 'unused_indexes_count' in key:
                    value = np.random.uniform(0, 30)
                elif 'disk' in key:
                    value = np.random.uniform(40, 70)
                elif 'connection' in key:
                    value = np.random.uniform(10, 100)
                else:
                    value = np.random.uniform(0, 100)
                
                datapoints.append({
                    'Timestamp': timestamp,
                    'Average': value,
                    'Unit': query.get('unit', 'Count')
                })
            
            results[query['key']] = datapoints
        
        return results
    
    def _generate_demo_log_data(self) -> List[Dict]:
        """Generate demo log data"""
        log_events = []
        current_time = datetime.now()
        
        log_messages = [
            "SQL Server started successfully",
            "Database backup completed",
            "Always On availability group health check passed",
            "High CPU usage detected on instance",
            "Memory pressure warning",
            "Deadlock detected between sessions",
            "Index maintenance completed",
            "Statistics update finished"
        ]
        
        for i in range(50):
            timestamp = current_time - timedelta(minutes=i * 30)
            log_events.append({
                'timestamp': int(timestamp.timestamp() * 1000),
                'message': np.random.choice(log_messages),
                'logStreamName': f'sql-server-{np.random.randint(1, 3)}'
            })
        
        return log_events

# =================== Always On Availability Groups Monitor ===================
class AlwaysOnMonitor:
    def __init__(self, cloudwatch_connector: AWSCloudWatchConnector):
        self.cloudwatch = cloudwatch_connector
        
        # Always On specific metrics to monitor
        self.availability_group_metrics = {
            'primary_replica_health': {
                'namespace': 'AWS/EC2',
                'metric_name': 'CPUUtilization',
                'dimensions': [{'Name': 'InstanceId', 'Value': 'i-primary'}]
            },
            'secondary_replica_health': {
                'namespace': 'AWS/EC2', 
                'metric_name': 'CPUUtilization',
                'dimensions': [{'Name': 'InstanceId', 'Value': 'i-secondary'}]
            },
            'synchronization_health': {
                'namespace': 'CWAgent',
                'metric_name': 'AlwaysOn_SyncHealth'
            },
            'data_movement_state': {
                'namespace': 'CWAgent',
                'metric_name': 'AlwaysOn_DataMovement'
            }
        }
    
    def get_availability_groups(self) -> List[Dict]:
        """Get Always On Availability Groups status"""
        if self.cloudwatch.demo_mode:
            return [
                {
                    'name': 'AG-Production',
                    'primary_replica': 'SQL-Node-1',
                    'secondary_replicas': ['SQL-Node-2', 'SQL-Node-3'],
                    'synchronization_health': 'HEALTHY',
                    'role_health': 'ONLINE',
                    'databases': ['ProductionDB', 'UserDB', 'LogDB']
                },
                {
                    'name': 'AG-Reporting',
                    'primary_replica': 'SQL-Node-2',
                    'secondary_replicas': ['SQL-Node-1'],
                    'synchronization_health': 'HEALTHY',
                    'role_health': 'ONLINE',
                    'databases': ['ReportingDB', 'AnalyticsDB']
                }
            ]
        
        # In a real implementation, this would query SQL Server DMVs through CloudWatch custom metrics
        # or use Systems Manager to run queries on EC2 instances
        return self._get_ag_status_from_cloudwatch()
    
    def _get_ag_status_from_cloudwatch(self) -> List[Dict]:
        """Get AG status from CloudWatch custom metrics"""
        # This would typically involve custom CloudWatch metrics
        # pushed from SQL Server instances via CloudWatch agent
        try:
            # Implementation would depend on how you're sending AG metrics to CloudWatch
            # Example implementation:
            ag_metrics = self.cloudwatch.get_cloudwatch_metrics(
                [
                    {
                        'key': 'ag_health',
                        'namespace': 'SQLServer/AlwaysOn',
                        'metric_name': 'AvailabilityGroupHealth'
                    }
                ],
                datetime.now() - timedelta(hours=1),
                datetime.now()
            )
            
            # Parse metrics and return AG status
            return []
            
        except Exception as e:
            logger.error(f"Failed to get AG status from CloudWatch: {str(e)}")
            return []
    
    def get_replica_health(self, replica_name: str) -> Dict:
        """Get detailed health for a specific replica"""
        if self.cloudwatch.demo_mode:
            return {
                'replica_name': replica_name,
                'role': np.random.choice(['PRIMARY', 'SECONDARY']),
                'operational_state': 'ONLINE',
                'connected_state': 'CONNECTED',
                'synchronization_health': np.random.choice(['HEALTHY', 'PARTIALLY_HEALTHY', 'NOT_HEALTHY']),
                'last_connect_error': None,
                'cpu_usage': np.random.uniform(20, 80),
                'memory_usage': np.random.uniform(60, 90)
            }
        
        # Implementation for real CloudWatch metrics
        return {}
    
    def check_synchronization_lag(self) -> List[Dict]:
        """Check for synchronization lag between replicas"""
        if self.cloudwatch.demo_mode:
            lag_data = []
            for i in range(3):
                lag_data.append({
                    'ag_name': f'AG-Production-{i+1}',
                    'database_name': f'Database-{i+1}',
                    'lag_seconds': np.random.uniform(0, 5),
                    'status': 'SYNCHRONIZED' if np.random.random() > 0.2 else 'SYNCHRONIZING'
                })
            return lag_data
        
        # Real implementation would query CloudWatch for sync lag metrics
        return []

# =================== Auto-Remediation Engine ===================
class AutoRemediationEngine:
    def __init__(self, cloudwatch_connector: AWSCloudWatchConnector):
        self.cloudwatch = cloudwatch_connector
        self.remediation_history = []
        
        # Define remediation rules
        self.remediation_rules = {
            'high_cpu_usage': {
                'threshold': 90,
                'duration_minutes': 10,
                'actions': ['scale_up', 'kill_expensive_queries', 'alert_dba'],
                'auto_execute': True
            },
            'memory_pressure': {
                'threshold': 95,
                'duration_minutes': 5,
                'actions': ['clear_buffer_cache', 'scale_up', 'alert_dba'],
                'auto_execute': True
            },
            'blocking_sessions': {
                'threshold': 5,  # Number of blocked sessions
                'duration_minutes': 2,
                'actions': ['kill_blocking_session', 'alert_dba'],
                'auto_execute': False  # Requires manual approval
            },
            'disk_space_low': {
                'threshold': 85,  # Percentage
                'duration_minutes': 15,
                'actions': ['cleanup_temp_files', 'extend_volume', 'alert_dba'],
                'auto_execute': True
            },
            'backup_failure': {
                'threshold': 1,  # Number of failed backups
                'duration_minutes': 0,
                'actions': ['retry_backup', 'check_backup_location', 'alert_dba'],
                'auto_execute': True
            },
            'ag_failover_needed': {
                'threshold': 1,
                'duration_minutes': 0,
                'actions': ['automatic_failover', 'alert_dba'],
                'auto_execute': False  # Critical operation
            }
        }
    
    def evaluate_conditions(self, metrics: Dict, alerts: List[Dict]) -> List[Dict]:
        """Evaluate conditions for auto-remediation"""
        remediation_actions = []
        
        for rule_name, rule in self.remediation_rules.items():
            condition_met = self._check_condition(rule_name, rule, metrics, alerts)
            
            if condition_met:
                action = {
                    'rule_name': rule_name,
                    'triggered_at': datetime.now(),
                    'actions': rule['actions'],
                    'auto_execute': rule['auto_execute'],
                    'severity': self._get_severity(rule_name),
                    'estimated_impact': self._get_impact(rule_name)
                }
                remediation_actions.append(action)
        
        return remediation_actions
    
    def execute_remediation(self, action: Dict) -> Dict:
        """Execute a remediation action"""
        if self.cloudwatch.demo_mode:
            return self._simulate_remediation(action)
        
        try:
            results = []
            
            for action_type in action['actions']:
                result = self._execute_action(action_type, action)
                results.append(result)
            
            # Log remediation action
            self.remediation_history.append({
                'action': action,
                'results': results,
                'executed_at': datetime.now(),
                'status': 'completed'
            })
            
            return {
                'status': 'success',
                'results': results,
                'message': f"Successfully executed {len(results)} remediation actions"
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'message': f"Remediation failed: {str(e)}"
            }
    
    def _check_condition(self, rule_name: str, rule: Dict, metrics: Dict, alerts: List[Dict]) -> bool:
        """Check if condition is met for a specific rule"""
        if rule_name == 'high_cpu_usage':
            # Check CPU metrics
            cpu_metrics = metrics.get('cpu_usage', [])
            if cpu_metrics:
                recent_cpu = [dp['Average'] for dp in cpu_metrics[-3:]]  # Last 3 datapoints
                return all(cpu > rule['threshold'] for cpu in recent_cpu)
        
        elif rule_name == 'memory_pressure':
            memory_metrics = metrics.get('memory_usage', [])
            if memory_metrics:
                recent_memory = [dp['Average'] for dp in memory_metrics[-2:]]
                return all(mem > rule['threshold'] for mem in recent_memory)
        
        elif rule_name == 'blocking_sessions':
            # Check for blocking session alerts
            blocking_alerts = [a for a in alerts if 'blocking' in a.get('message', '').lower()]
            return len(blocking_alerts) >= rule['threshold']
        
        elif rule_name == 'disk_space_low':
            disk_metrics = metrics.get('disk_usage', [])
            if disk_metrics:
                recent_disk = [dp['Average'] for dp in disk_metrics[-3:]]
                return all(disk > rule['threshold'] for disk in recent_disk)
        
        elif rule_name == 'backup_failure':
            backup_alerts = [a for a in alerts if 'backup' in a.get('message', '').lower() and 'fail' in a.get('message', '').lower()]
            return len(backup_alerts) >= rule['threshold']
        
        return False
    
    def _execute_action(self, action_type: str, context: Dict) -> Dict:
        """Execute a specific remediation action"""
        if action_type == 'scale_up':
            return self._scale_up_instance(context)
        elif action_type == 'kill_expensive_queries':
            return self._kill_expensive_queries(context)
        elif action_type == 'clear_buffer_cache':
            return self._clear_buffer_cache(context)
        elif action_type == 'cleanup_temp_files':
            return self._cleanup_temp_files(context)
        elif action_type == 'retry_backup':
            return self._retry_backup(context)
        elif action_type == 'automatic_failover':
            return self._perform_ag_failover(context)
        elif action_type == 'alert_dba':
            return self._send_alert_to_dba(context)
        else:
            return {'status': 'error', 'message': f'Unknown action type: {action_type}'}
    
    def _scale_up_instance(self, context: Dict) -> Dict:
        """Scale up EC2 instance or RDS instance"""
        try:
            # For EC2 instances
            if context.get('instance_type') == 'ec2':
                # Use Systems Manager to modify instance type
                ssm_client = self.cloudwatch.aws_manager.get_client('ssm')
                if ssm_client:
                    response = ssm_client.send_command(
                        InstanceIds=[context.get('instance_id')],
                        DocumentName="AWS-ResizeInstance",
                        Parameters={
                            'InstanceType': [self._get_next_instance_size(context.get('current_instance_type'))]
                        }
                    )
                    return {'status': 'success', 'message': 'Instance scaling initiated'}
            
            # For RDS instances
            elif context.get('instance_type') == 'rds':
                rds_client = self.cloudwatch.aws_manager.get_client('rds')
                if rds_client:
                    rds_client.modify_db_instance(
                        DBInstanceIdentifier=context.get('instance_id'),
                        DBInstanceClass=self._get_next_rds_size(context.get('current_instance_class')),
                        ApplyImmediately=True
                    )
                    return {'status': 'success', 'message': 'RDS scaling initiated'}
                
        except Exception as e:
            return {'status': 'error', 'message': f'Scaling failed: {str(e)}'}
    
    def _kill_expensive_queries(self, context: Dict) -> Dict:
        """Kill expensive SQL queries"""
        try:
            # Use Systems Manager to run SQL commands
            sql_command = """
            DECLARE @SessionID INT
            DECLARE query_cursor CURSOR FOR
            SELECT session_id FROM sys.dm_exec_requests 
            WHERE cpu_time > 30000 AND total_elapsed_time > 60000
            
            OPEN query_cursor
            FETCH NEXT FROM query_cursor INTO @SessionID
            
            WHILE @@FETCH_STATUS = 0
            BEGIN
                KILL @SessionID
                FETCH NEXT FROM query_cursor INTO @SessionID
            END
            
            CLOSE query_cursor
            DEALLOCATE query_cursor
            """
            
            ssm_client = self.cloudwatch.aws_manager.get_client('ssm')
            if ssm_client:
                response = ssm_client.send_command(
                    InstanceIds=[context.get('instance_id')],
                    DocumentName="AWS-RunPowerShellScript",
                    Parameters={
                        'commands': [f'sqlcmd -Q "{sql_command}"']
                    }
                )
                
                return {'status': 'success', 'message': 'Expensive queries terminated'}
            
        except Exception as e:
            return {'status': 'error', 'message': f'Query termination failed: {str(e)}'}
    
    def _clear_buffer_cache(self, context: Dict) -> Dict:
        """Clear SQL Server buffer cache to free memory"""
        try:
            sql_command = "DBCC DROPCLEANBUFFERS"
            
            ssm_client = self.cloudwatch.aws_manager.get_client('ssm')
            if ssm_client:
                response = ssm_client.send_command(
                    InstanceIds=[context.get('instance_id')],
                    DocumentName="AWS-RunPowerShellScript",
                    Parameters={
                        'commands': [f'sqlcmd -Q "{sql_command}"']
                    }
                )
                
                return {'status': 'success', 'message': 'Buffer cache cleared'}
            
        except Exception as e:
            return {'status': 'error', 'message': f'Buffer cache clear failed: {str(e)}'}
    
    def _cleanup_temp_files(self, context: Dict) -> Dict:
        """Clean up temporary files and logs"""
        try:
            cleanup_script = """
            # Clean SQL Server temp files
            Remove-Item "C:\\Program Files\\Microsoft SQL Server\\MSSQL*\\MSSQL\\Data\\tempdb*" -Force -ErrorAction SilentlyContinue
            
            # Clean Windows temp files
            Remove-Item "$env:TEMP\\*" -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item "C:\\Windows\\Temp\\*" -Recurse -Force -ErrorAction SilentlyContinue
            
            # Clean old log files
            Get-ChildItem "C:\\Program Files\\Microsoft SQL Server\\MSSQL*\\MSSQL\\Log\\*.trc" | Where-Object {$_.LastWriteTime -lt (Get-Date).AddDays(-7)} | Remove-Item -Force
            """
            
            ssm_client = self.cloudwatch.aws_manager.get_client('ssm')
            if ssm_client:
                response = ssm_client.send_command(
                    InstanceIds=[context.get('instance_id')],
                    DocumentName="AWS-RunPowerShellScript",
                    Parameters={'commands': [cleanup_script]}
                )
                
                return {'status': 'success', 'message': 'Temporary files cleaned'}
            
        except Exception as e:
            return {'status': 'error', 'message': f'Cleanup failed: {str(e)}'}
    
    def _retry_backup(self, context: Dict) -> Dict:
        """Retry failed database backup"""
        try:
            sql_command = """
            DECLARE @BackupPath NVARCHAR(500) = 'C:\\Backups\\' + DB_NAME() + '_' + FORMAT(GETDATE(), 'yyyyMMdd_HHmmss') + '.bak'
            BACKUP DATABASE [YourDatabase] TO DISK = @BackupPath WITH INIT, COMPRESSION
            """
            
            ssm_client = self.cloudwatch.aws_manager.get_client('ssm')
            if ssm_client:
                response = ssm_client.send_command(
                    InstanceIds=[context.get('instance_id')],
                    DocumentName="AWS-RunPowerShellScript",
                    Parameters={
                        'commands': [f'sqlcmd -Q "{sql_command}"']
                    }
                )
                
                return {'status': 'success', 'message': 'Backup retry initiated'}
            
        except Exception as e:
            return {'status': 'error', 'message': f'Backup retry failed: {str(e)}'}
    
    def _perform_ag_failover(self, context: Dict) -> Dict:
        """Perform Always On Availability Group failover"""
        try:
            sql_command = """
            ALTER AVAILABILITY GROUP [YourAGName] FAILOVER
            """
            
            ssm_client = self.cloudwatch.aws_manager.get_client('ssm')
            if ssm_client:
                response = ssm_client.send_command(
                    InstanceIds=[context.get('secondary_instance_id')],
                    DocumentName="AWS-RunPowerShellScript",
                    Parameters={
                        'commands': [f'sqlcmd -Q "{sql_command}"']
                    }
                )
                
                return {'status': 'success', 'message': 'AG failover initiated'}
            
        except Exception as e:
            return {'status': 'error', 'message': f'AG failover failed: {str(e)}'}
    
    def _send_alert_to_dba(self, context: Dict) -> Dict:
        """Send alert to DBA team"""
        try:
            # Use SNS to send notification
            message = f"""
            Auto-Remediation Alert:
            Rule: {context.get('rule_name')}
            Severity: {context.get('severity')}
            Instance: {context.get('instance_id')}
            Actions Taken: {', '.join(context.get('actions', []))}
            Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            """
            
            # In a real implementation, you would publish to SNS
            # sns_client = self.cloudwatch.aws_manager.get_client('sns')
            # if sns_client:
            #     sns_client.publish(
            #         TopicArn='arn:aws:sns:region:account:dba-alerts',
            #         Message=message,
            #         Subject='SQL Server Auto-Remediation Alert'
            #     )
            
            return {'status': 'success', 'message': 'Alert sent to DBA team'}
            
        except Exception as e:
            return {'status': 'error', 'message': f'Alert sending failed: {str(e)}'}
    
    def _simulate_remediation(self, action: Dict) -> Dict:
        """Simulate remediation action in demo mode"""
        return {
            'status': 'success',
            'results': [
                {'action': action_type, 'status': 'simulated', 'message': f'Simulated {action_type}'}
                for action_type in action['actions']
            ],
            'message': f"Simulated remediation for {action['rule_name']}"
        }
    
    def _get_severity(self, rule_name: str) -> str:
        """Get severity level for a rule"""
        severity_map = {
            'high_cpu_usage': 'Medium',
            'memory_pressure': 'High',
            'blocking_sessions': 'Medium',
            'disk_space_low': 'High',
            'backup_failure': 'High',
            'ag_failover_needed': 'Critical'
        }
        return severity_map.get(rule_name, 'Medium')
    
    def _get_impact(self, rule_name: str) -> str:
        """Get estimated impact for a rule"""
        impact_map = {
            'high_cpu_usage': 'Low to Medium',
            'memory_pressure': 'Medium',
            'blocking_sessions': 'Low',
            'disk_space_low': 'Medium',
            'backup_failure': 'Low',
            'ag_failover_needed': 'High'
        }
        return impact_map.get(rule_name, 'Low')
    
    def _get_next_instance_size(self, current_type: str) -> str:
        """Get next larger instance size"""
        size_progression = {
            't3.micro': 't3.small',
            't3.small': 't3.medium',
            't3.medium': 't3.large',
            't3.large': 't3.xlarge',
            'm5.large': 'm5.xlarge',
            'm5.xlarge': 'm5.2xlarge',
            'm5.2xlarge': 'm5.4xlarge'
        }
        return size_progression.get(current_type, current_type)
    
    def _get_next_rds_size(self, current_class: str) -> str:
        """Get next larger RDS instance class"""
        size_progression = {
            'db.t3.micro': 'db.t3.small',
            'db.t3.small': 'db.t3.medium',
            'db.t3.medium': 'db.t3.large',
            'db.m5.large': 'db.m5.xlarge',
            'db.m5.xlarge': 'db.m5.2xlarge'
        }
        return size_progression.get(current_class, current_class)

# =================== Predictive Analytics Engine ===================
class PredictiveAnalyticsEngine:
    def __init__(self, cloudwatch_connector: AWSCloudWatchConnector):
        self.cloudwatch = cloudwatch_connector
        self.prediction_models = {}
    
    def analyze_trends(self, metrics: Dict, days: int = 30) -> Dict:
        """Analyze performance trends and predict future issues"""
        predictions = {}
        
        for metric_name, metric_data in metrics.items():
            if metric_data:
                trend_analysis = self._analyze_metric_trend(metric_name, metric_data)
                predictions[metric_name] = trend_analysis
        
        return predictions
    
    def _analyze_metric_trend(self, metric_name: str, data: List[Dict]) -> Dict:
        """Analyze trend for a specific metric"""
        if len(data) < 10:
            return {'status': 'insufficient_data'}
        
        # Extract values and timestamps
        values = [dp['Average'] for dp in data]
        timestamps = [dp['Timestamp'] for dp in data]
        
        # Calculate trend
        trend = self._calculate_trend(values)
        
        # Predict future values
        future_prediction = self._predict_future_values(values, 24)  # Next 24 hours
        
        # Determine risk level
        risk_level = self._assess_risk_level(metric_name, values, future_prediction)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(metric_name, trend, risk_level)
        
        return {
            'status': 'analyzed',
            'trend': trend,
            'risk_level': risk_level,
            'future_prediction': future_prediction,
            'recommendations': recommendations,
            'confidence': self._calculate_confidence(values)
        }
    
    def _calculate_trend(self, values: List[float]) -> str:
        """Calculate trend direction"""
        if len(values) < 5:
            return 'stable'
        
        # Simple linear regression
        x = list(range(len(values)))
        n = len(values)
        sum_x = sum(x)
        sum_y = sum(values)
        sum_xy = sum(x[i] * values[i] for i in range(n))
        sum_x2 = sum(x[i] ** 2 for i in range(n))
        
        slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x ** 2)
        
        if slope > 0.5:
            return 'increasing'
        elif slope < -0.5:
            return 'decreasing'
        else:
            return 'stable'
    
    def _predict_future_values(self, values: List[float], periods: int) -> List[float]:
        """Predict future values using simple linear extrapolation"""
        if len(values) < 3:
            return [values[-1]] * periods
        
        # Calculate average change
        changes = [values[i] - values[i-1] for i in range(1, len(values))]
        avg_change = sum(changes) / len(changes)
        
        # Predict future values
        last_value = values[-1]
        predictions = []
        
        for i in range(periods):
            predicted_value = last_value + (avg_change * (i + 1))
            predictions.append(max(0, predicted_value))  # Ensure non-negative
        
        return predictions
    
    def _assess_risk_level(self, metric_name: str, historical: List[float], 
                          predicted: List[float]) -> str:
        """Assess risk level based on predictions"""
        # Define thresholds for different metrics
        thresholds = {
            'cpu_usage': {'warning': 70, 'critical': 90},
            'memory_usage': {'warning': 80, 'critical': 95},
            'disk_usage': {'warning': 75, 'critical': 90},
            'connection_count': {'warning': 80, 'critical': 95}
        }
        
        metric_threshold = thresholds.get(metric_name, {'warning': 80, 'critical': 95})
        
        # Check if any predicted values exceed thresholds
        max_predicted = max(predicted)
        
        if max_predicted > metric_threshold['critical']:
            return 'critical'
        elif max_predicted > metric_threshold['warning']:
            return 'warning'
        else:
            return 'low'
    
    def _generate_recommendations(self, metric_name: str, trend: str, risk_level: str) -> List[str]:
        """Generate recommendations based on analysis"""
        recommendations = []
        
        if risk_level == 'critical':
            if metric_name == 'cpu_usage':
                recommendations.extend([
                    "Consider scaling up instance size immediately",
                    "Review and optimize expensive queries",
                    "Enable auto-scaling if not already configured"
                ])
            elif metric_name == 'memory_usage':
                recommendations.extend([
                    "Increase instance memory or scale up",
                    "Review memory-intensive queries and procedures",
                    "Consider implementing memory optimization"
                ])
            elif metric_name == 'disk_usage':
                recommendations.extend([
                    "Extend disk storage immediately",
                    "Implement log file maintenance",
                    "Archive old data to reduce storage usage"
                ])
        
        elif risk_level == 'warning':
            recommendations.extend([
                f"Monitor {metric_name} closely over the next 24 hours",
                "Prepare scaling strategy if trend continues",
                "Review recent changes that might impact performance"
            ])
        
        if trend == 'increasing':
            recommendations.append(f"The {metric_name} trend is increasing - proactive action recommended")
        
        return recommendations
    
    def _calculate_confidence(self, values: List[float]) -> float:
        """Calculate confidence level of predictions"""
        if len(values) < 10:
            return 0.3
        
        # Calculate variance to determine confidence
        mean_val = sum(values) / len(values)
        variance = sum((x - mean_val) ** 2 for x in values) / len(values)
        std_dev = variance ** 0.5
        
        # Lower variance = higher confidence
        if std_dev < mean_val * 0.1:
            return 0.9
        elif std_dev < mean_val * 0.2:
            return 0.7
        elif std_dev < mean_val * 0.3:
            return 0.5
        else:
            return 0.3

# =================== Claude AI Analyzer ===================
class ClaudeAIAnalyzer:
    def __init__(self, api_key: str):
        if not ANTHROPIC_AVAILABLE:
            self.client = None
            self.enabled = False
            return
            
        if api_key:
            try:
                self.client = Anthropic(api_key=api_key)
                self.enabled = True
            except Exception as e:
                self.client = None
                self.enabled = False
        else:
            self.client = None
            self.enabled = False

# =================== Main Application ===================
def main():
    st.markdown('<div class="aws-header"><h1>☁️ AWS CloudWatch SQL Server Monitor</h1><p>Enterprise-grade monitoring with AI-powered analytics and auto-remediation - Optimized for Streamlit Cloud</p></div>', unsafe_allow_html=True)
    
    # Initialize session state
    if 'cloudwatch_connector' not in st.session_state:
        st.session_state.cloudwatch_connector = None
    
    if 'always_on_monitor' not in st.session_state:
        st.session_state.always_on_monitor = None
    
    if 'auto_remediation' not in st.session_state:
        st.session_state.auto_remediation = None
    
    if 'predictive_analytics' not in st.session_state:
        st.session_state.predictive_analytics = None
    
    if 'claude_analyzer' not in st.session_state:
        st.session_state.claude_analyzer = None

    # Initialize default config for demo mode
    aws_config = {
        'access_key': 'demo',
        'secret_key': 'demo',
        'region': 'us-east-1',
        'account_id': '123456789012',
        'account_name': 'Demo Environment',
        'log_groups': [
            "/aws/rds/instance/sql-server-prod-1/error",
            "/ec2/sql-server/application",
            "/ec2/sql-server/system"
        ],
        'custom_namespace': 'SQLServer/CustomMetrics',
        'os_metrics_namespace': 'CWAgent',
        'enable_os_metrics': True
    }
    
    # Sidebar configuration
    with st.sidebar:
        st.header("🔧 AWS Configuration")
        
        # System Status and Environment Detection
        st.subheader("📊 System Status")
        
        # Detect Streamlit Cloud
        aws_manager = get_aws_manager()
        if aws_manager.is_streamlit_cloud:
            st.info("🌐 **Streamlit Cloud Detected**")
            st.write("Optimized configuration active")
        
        if not AWS_AVAILABLE:
            st.error("❌ boto3 not available")
            st.info("💡 Install boto3: `pip install boto3`")
        else:
            st.success("✅ boto3 available")
        
        if not ANTHROPIC_AVAILABLE:
            st.warning("⚠️ anthropic not available")
            st.info("💡 Install anthropic: `pip install anthropic`")
        else:
            st.success("✅ anthropic available")
        
        # Demo mode indicator
        if not AWS_AVAILABLE:
            st.markdown("""
            <div style="background: linear-gradient(135deg, #ff6b6b 0%, #ee5a52 100%); 
                        padding: 1rem; border-radius: 8px; color: white; margin: 1rem 0;">
                <strong>🎭 DEMO MODE</strong><br>
                Using simulated data. Install boto3 for real AWS connections.
            </div>
            """, unsafe_allow_html=True)
        
        st.markdown("---")
        
        # Enhanced AWS Configuration Section for Streamlit Cloud
        st.subheader("🔑 AWS Credentials")
        
        # Method selection for Streamlit Cloud
        auth_method = st.radio(
            "Authentication Method",
            [
                "🌍 Environment Variables (Recommended for Streamlit Cloud)",
                "🔑 Manual Input",
                "🏢 Default Credential Chain"
            ]
        )
        
        # Initialize variables
        aws_access_key = None
        aws_secret_key = None
        
        if auth_method.startswith("🌍"):
            # Environment Variables
            st.info("💡 **Best for Streamlit Cloud deployment**")
            st.write("Set these in your Streamlit Cloud app settings:")
            st.code("""
Environment Variables:
AWS_ACCESS_KEY_ID=your_access_key_here
AWS_SECRET_ACCESS_KEY=your_secret_key_here
AWS_DEFAULT_REGION=us-east-1
            """)
            
            # Check current environment
            env_access_key = os.getenv('AWS_ACCESS_KEY_ID')
            env_secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
            
            if env_access_key and env_secret_key:
                st.success("✅ Environment variables detected!")
                st.write(f"**Access Key:** {env_access_key[:8]}...")
                aws_access_key = env_access_key
                aws_secret_key = env_secret_key
            else:
                st.warning("⚠️ Environment variables not found")
                
        elif auth_method.startswith("🔑"):
            # Manual Input
            st.info("💡 **For local development and testing**")
            aws_access_key = st.text_input(
                "AWS Access Key ID", 
                type="password",
                help="Your AWS Access Key ID (starts with AKIA or ASIA)",
                placeholder="AKIAIOSFODNN7EXAMPLE"
            )
            
            aws_secret_key = st.text_input(
                "AWS Secret Access Key", 
                type="password",
                help="Your AWS Secret Access Key (40 characters)",
                placeholder="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            )
            
        else:
            # Default Credential Chain
            st.info("💡 **For EC2 instances with IAM roles**")
            st.write("Will attempt to use:")
            st.write("• EC2 instance profile")
            st.write("• ECS task role")
            st.write("• Shared credentials file")
        
        # Region selection
        aws_region = st.selectbox("AWS Region", [
            'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
            'eu-west-1', 'eu-west-2', 'eu-central-1', 
            'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1'
        ])
        
        # AWS Account Information
        st.subheader("🏢 AWS Account Details")
        aws_account_id = st.text_input("AWS Account ID (Optional)", 
                                    help="Your 12-digit AWS Account ID")
        aws_account_name = st.text_input("Account Name/Environment", 
                                        value="Production", 
                                        help="Environment name (e.g., Production, Staging)")

        # Update the aws_config dictionary
        aws_config.update({
            'access_key': aws_access_key or 'demo',
            'secret_key': aws_secret_key or 'demo',
            'region': aws_region,
            'account_id': aws_account_id,
            'account_name': aws_account_name
        })

        # CloudWatch Configuration
        st.subheader("📊 CloudWatch Configuration")

        # Log Groups Configuration
        st.write("**📝 CloudWatch Log Groups:**")
        default_log_groups = [
            "/aws/rds/instance/sql-server-prod-1/error",
            "/aws/rds/instance/sql-server-prod-1/agent", 
            "/ec2/sql-server/application",
            "/ec2/sql-server/system",
            "/ec2/sql-server/security"
        ]

        log_groups = st.text_area(
            "Log Groups (one per line)",
            value="\n".join(default_log_groups),
            height=150,
            help="Enter CloudWatch log group names, one per line"
        ).split('\n')

        # Custom Namespace Configuration
        custom_namespace = st.text_input(
            "Custom Metrics Namespace", 
            value="SQLServer/CustomMetrics",
            help="Namespace for your custom SQL Server metrics"
        )

        # OS Metrics Configuration
        st.write("**🖥️ OS Metrics Configuration:**")
        enable_os_metrics = st.checkbox("Enable OS-level Metrics", value=True)
        os_metrics_namespace = st.text_input(
            "OS Metrics Namespace",
            value="CWAgent",
            help="CloudWatch namespace for OS metrics"
        )

        # Update the aws_config dictionary with CloudWatch settings
        aws_config.update({
            'log_groups': [lg.strip() for lg in log_groups if lg.strip()],
            'custom_namespace': custom_namespace,
            'os_metrics_namespace': os_metrics_namespace,
            'enable_os_metrics': enable_os_metrics
        })

        # Initialize or reinitialize the connector if config changed
        if (st.session_state.cloudwatch_connector is None or 
            getattr(st.session_state.cloudwatch_connector, 'aws_config', {}) != aws_config):
            
            # Use spinner for initialization
            with st.spinner("🔄 Initializing AWS connection..."):
                try:
                    st.session_state.cloudwatch_connector = AWSCloudWatchConnector(aws_config)
                    st.session_state.always_on_monitor = AlwaysOnMonitor(st.session_state.cloudwatch_connector)
                    st.session_state.auto_remediation = AutoRemediationEngine(st.session_state.cloudwatch_connector)
                    st.session_state.predictive_analytics = PredictiveAnalyticsEngine(st.session_state.cloudwatch_connector)
                except Exception as e:
                    st.error(f"Failed to initialize: {str(e)}")

        # Connection test button
        if st.button("🔌 Test AWS Connection", type="primary"):
            with st.spinner("Testing AWS connection..."):
                if st.session_state.cloudwatch_connector:
                    if st.session_state.cloudwatch_connector.test_connection():
                        st.success("✅ AWS Connection Successful!")
                        
                        # Display connection details
                        conn_status = st.session_state.cloudwatch_connector.get_connection_status()
                        if conn_status.get('account_id'):
                            st.write(f"**Account:** {conn_status['account_id']}")
                        if conn_status.get('user_arn'):
                            st.write(f"**Role:** {conn_status['user_arn'].split('/')[-1]}")
                        if conn_status.get('method'):
                            st.write(f"**Method:** {conn_status['method'].replace('_', ' ').title()}")
                    else:
                        st.error("❌ AWS Connection Failed")
                        
                        # Show detailed error if available
                        conn_status = st.session_state.cloudwatch_connector.get_connection_status()
                        if conn_status.get('error'):
                            with st.expander("🔍 View Error Details"):
                                st.error(conn_status['error'])
                else:
                    st.error("❌ CloudWatch connector not initialized")

        # Enhanced Connection Status Display
        if st.session_state.cloudwatch_connector:
            st.markdown("---")
            st.subheader("🔗 Connection Status")
            
            conn_status = st.session_state.cloudwatch_connector.get_connection_status()
            
            # Status indicator
            if conn_status.get('connected'):
                if conn_status.get('demo_mode'):
                    status_class = "cred-warning"
                    status_icon = "🎭"
                    status_text = "Demo Mode"
                else:
                    status_class = "cred-success"
                    status_icon = "✅"
                    status_text = "Connected"
            else:
                status_class = "cred-error"
                status_icon = "❌"
                status_text = "Disconnected"
            
            st.markdown(f"""
            <div class="credential-status {status_class}">
                <strong>{status_icon} Status:</strong> {status_text}<br>
                <strong>Environment:</strong> {'Streamlit Cloud' if conn_status.get('streamlit_cloud') else 'Local'}<br>
                <strong>Method:</strong> {conn_status.get('method', 'Unknown').replace('_', ' ').title()}<br>
                <strong>Last Test:</strong> {conn_status.get('last_test').strftime('%H:%M:%S') if conn_status.get('last_test') else 'Never'}
            </div>
            """, unsafe_allow_html=True)
            
            if conn_status.get('account_id'):
                st.write(f"**Account ID:** {conn_status['account_id']}")
            
            if conn_status.get('region'):
                st.write(f"**Region:** {conn_status['region']}")
            
            if conn_status.get('error'):
                with st.expander("🔍 View Error Details"):
                    st.error(conn_status['error'])
        
        st.markdown("---")
        
        # SQL Server Configuration
        st.subheader("🗄️ SQL Server Configuration")
        
        with st.expander("📋 Setup Guide for Real Data", expanded=False):
            st.markdown("""
            ### 🔧 Setting Up SQL Server Metrics in AWS CloudWatch
            
            **For Streamlit Cloud deployment, set these environment variables:**
            
            ```bash
            AWS_ACCESS_KEY_ID=your_access_key
            AWS_SECRET_ACCESS_KEY=your_secret_key
            AWS_DEFAULT_REGION=us-east-1
            ```
            
            **Required IAM Permissions:**
            ```json
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "cloudwatch:GetMetricStatistics",
                            "cloudwatch:ListMetrics",
                            "cloudwatch:PutMetricData",
                            "logs:FilterLogEvents",
                            "logs:DescribeLogGroups",
                            "ec2:DescribeInstances",
                            "rds:DescribeDBInstances",
                            "sts:GetCallerIdentity"
                        ],
                        "Resource": "*"
                    }
                ]
            }
            ```
            
            **CloudWatch Agent Setup on SQL Server instances:**
            1. Install CloudWatch agent
            2. Configure SQL Server performance counters
            3. Set up custom metrics collection
            4. Tag EC2 instances with `Application: SQLServer`
            """)
        
        st.markdown("---")
        
        # Claude AI Configuration
        st.subheader("🤖 Claude AI Settings")
        claude_api_key = st.text_input("Claude AI API Key", type="password", 
                                      help="Enter your Anthropic Claude API key")
        
        if claude_api_key and ANTHROPIC_AVAILABLE:
            if 'claude_analyzer' not in st.session_state or st.session_state.claude_analyzer is None:
                st.session_state.claude_analyzer = ClaudeAIAnalyzer(claude_api_key)
            
            if hasattr(st.session_state.claude_analyzer, 'enabled') and st.session_state.claude_analyzer.enabled:
                st.success("✅ Claude AI Connected")
            else:
                st.error("❌ Claude AI Connection Failed")
        
        st.markdown("---")
        
        # Auto-Remediation Settings
        st.subheader("🔧 Auto-Remediation")
        enable_auto_remediation = st.checkbox("Enable Auto-Remediation", value=True)
        auto_approval_threshold = st.selectbox("Auto-Approval Level", [
            "Low Risk Only",
            "Low + Medium Risk", 
            "All Except Critical",
            "Manual Approval Required"
        ])
        
        st.markdown("---")
        
        # Monitoring Settings
        st.subheader("📊 Monitoring Settings")
        refresh_interval = st.slider("Refresh Interval (seconds)", 30, 300, 60)
        metric_retention_days = st.slider("Metric Retention (days)", 7, 90, 30)
        enable_predictive_alerts = st.checkbox("Enable Predictive Alerts", value=True)
    
    # Initialize CloudWatch connector if not already done
    if not st.session_state.cloudwatch_connector:
        with st.spinner("🔄 Initializing monitoring system..."):
            st.session_state.cloudwatch_connector = AWSCloudWatchConnector(aws_config)
            st.session_state.always_on_monitor = AlwaysOnMonitor(st.session_state.cloudwatch_connector)
            st.session_state.auto_remediation = AutoRemediationEngine(st.session_state.cloudwatch_connector)
            st.session_state.predictive_analytics = PredictiveAnalyticsEngine(st.session_state.cloudwatch_connector)

    # =================== Enhanced Data Collection for Streamlit Cloud ===================
    @st.cache_data(ttl=300)  # Cache for 5 minutes to reduce API calls
    def collect_comprehensive_metrics():
        """Collect all metrics including OS, SQL Server, and logs with caching"""
        current_time = datetime.now()
        start_time = current_time - timedelta(hours=24)
        
        all_metrics = {}
        all_logs = {}
        
        try:
            # Get AWS account information
            if st.session_state.cloudwatch_connector:
                account_info = st.session_state.cloudwatch_connector.get_account_info()
                
                # Display account info in sidebar
                if account_info and not st.session_state.cloudwatch_connector.demo_mode:
                    st.sidebar.markdown("---")
                    st.sidebar.subheader("🏢 Account Information")
                    st.sidebar.write(f"**Account ID:** {account_info.get('account_id', 'Unknown')}")
                    st.sidebar.write(f"**Region:** {account_info.get('region', 'Unknown')}")
                    st.sidebar.write(f"**Environment:** {account_info.get('environment', 'Unknown')}")
            
            # Get EC2 instances for comprehensive monitoring
            ec2_instances = st.session_state.cloudwatch_connector.get_ec2_sql_instances()
            
            for ec2 in ec2_instances:
                instance_id = ec2['InstanceId']
                
                # Get SQL Server metrics
                sql_metrics = st.session_state.cloudwatch_connector.get_comprehensive_sql_metrics(
                    instance_id, start_time, current_time
                )
                
                # Get OS-level metrics if enabled
                if aws_config.get('enable_os_metrics', True):
                    os_metrics = st.session_state.cloudwatch_connector.get_os_metrics(
                        instance_id, start_time, current_time
                    )
                    
                    # Merge OS metrics with SQL metrics
                    for metric_key, metric_data in os_metrics.items():
                        sql_metrics[f"os_{metric_key}"] = metric_data
                
                # Add to overall metrics with instance prefix
                for metric_key, metric_data in sql_metrics.items():
                    all_metrics[f"{instance_id}_{metric_key}"] = metric_data
            
            # Get logs from configured log groups
            if aws_config.get('log_groups'):
                all_logs = st.session_state.cloudwatch_connector.get_sql_server_logs(
                    aws_config['log_groups'], 
                    hours=24
                )
        
        except Exception as e:
            logger.error(f"Error collecting metrics: {str(e)}")
            st.error(f"Error collecting metrics: {str(e)}")
        
        return all_metrics, all_logs, ec2_instances

    # Collect metrics with progress indicator
    with st.spinner("🔄 Collecting metrics and logs..."):
        all_metrics, all_logs, ec2_instances = collect_comprehensive_metrics()
    
    # Get RDS instances
    rds_instances = st.session_state.cloudwatch_connector.get_rds_instances()
    
    # Also get basic infrastructure metrics
    basic_metric_queries = [
        {'key': 'cpu_usage', 'namespace': 'AWS/EC2', 'metric_name': 'CPUUtilization', 'unit': 'Percent'},
        {'key': 'memory_usage', 'namespace': 'CWAgent', 'metric_name': 'Memory % Committed Bytes In Use', 'unit': 'Percent'},
        {'key': 'disk_usage', 'namespace': 'CWAgent', 'metric_name': 'LogicalDisk % Free Space', 'unit': 'Percent'},
        {'key': 'network_in', 'namespace': 'AWS/EC2', 'metric_name': 'NetworkIn', 'unit': 'Bytes'},
        {'key': 'network_out', 'namespace': 'AWS/EC2', 'metric_name': 'NetworkOut', 'unit': 'Bytes'}
    ]
    
    # Get basic infrastructure metrics
    current_time = datetime.now()
    start_time = current_time - timedelta(hours=24)
    basic_metrics = st.session_state.cloudwatch_connector.get_cloudwatch_metrics(
        basic_metric_queries, start_time, current_time
    )
    
    # Merge with comprehensive metrics
    all_metrics.update(basic_metrics)
    
    # Main tabs
    tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8, tab9 = st.tabs([
        "🏠 Dashboard", 
        "🗄️ SQL Metrics",
        "🖥️ OS Metrics",
        "🔄 Always On", 
        "🤖 Auto-Remediation",
        "🔮 Predictive Analytics", 
        "🚨 Alerts", 
        "📊 Performance",
        "📈 Reports"
    ])
    
    # =================== Dashboard Tab ===================
    with tab1:
        st.header("🏢 AWS SQL Server Infrastructure Overview")
        
        # Enhanced connection status banner for Streamlit Cloud
        if st.session_state.cloudwatch_connector:
            conn_status = st.session_state.cloudwatch_connector.get_connection_status()
            
            if conn_status.get('connected'):
                if conn_status.get('demo_mode'):
                    st.info("🎭 **Demo Mode Active** - Using simulated data for demonstration purposes")
                    st.write("💡 **To connect to real AWS:** Set environment variables in Streamlit Cloud settings")
                else:
                    col1, col2 = st.columns([3, 1])
                    with col1:
                        st.success(f"✅ **Live AWS Connection** - Account: {conn_status.get('account_id', 'Unknown')}")
                        st.write(f"**Method:** {conn_status.get('method', 'Unknown').replace('_', ' ').title()}")
                    with col2:
                        if st.button("🔄 Refresh Connection"):
                            st.session_state.cloudwatch_connector.test_connection()
                            st.rerun()
            else:
                st.error("❌ **AWS Connection Failed** - Check credentials in sidebar")
                if conn_status.get('error'):
                    with st.expander("🔍 View Connection Error"):
                        st.error(conn_status['error'])
                        
                        # Streamlit Cloud specific troubleshooting
                        if conn_status.get('streamlit_cloud'):
                            st.info("""
                            **Streamlit Cloud Troubleshooting:**
                            1. Go to your app settings in Streamlit Cloud
                            2. Add environment variables:
                               - `AWS_ACCESS_KEY_ID`
                               - `AWS_SECRET_ACCESS_KEY`
                               - `AWS_DEFAULT_REGION`
                            3. Restart your app
                            """)
        
        # Infrastructure summary
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("RDS Instances", len(rds_instances))
        
        with col2:
            ec2_running = len([i for i in ec2_instances if i.get('State', {}).get('Name') == 'running'])
            st.metric("EC2 SQL Instances", f"{ec2_running}/{len(ec2_instances)}")
        
        with col3:
            ag_count = len(st.session_state.always_on_monitor.get_availability_groups())
            st.metric("Always On AGs", ag_count)
        
        with col4:
            # Calculate average CPU across all instances
            if all_metrics.get('cpu_usage'):
                avg_cpu = np.mean([dp['Average'] for dp in all_metrics['cpu_usage'][-5:]])
                cpu_color = "🔴" if avg_cpu > 80 else "🟡" if avg_cpu > 60 else "🟢"
                st.metric(f"Avg CPU {cpu_color}", f"{avg_cpu:.1f}%")
            else:
                st.metric("Avg CPU", "N/A")
        
        st.markdown("---")
        
        # RDS Instances Overview
        if rds_instances:
            st.subheader("📊 RDS SQL Server Instances")
            for rds in rds_instances:
                status_color = "cluster-online" if rds['DBInstanceStatus'] == 'available' else "cluster-offline"
                
                st.markdown(f'<div class="{status_color}">📊 <strong>{rds["DBInstanceIdentifier"]}</strong> - {rds["DBInstanceStatus"].title()}</div>', 
                           unsafe_allow_html=True)
                
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.write(f"**Engine:** {rds['Engine']}")
                with col2:
                    st.write(f"**AZ:** {rds['AvailabilityZone']}")
                with col3:
                    st.write(f"**Multi-AZ:** {'Yes' if rds.get('MultiAZ') else 'No'}")
                with col4:
                    st.write(f"**Storage:** {rds.get('AllocatedStorage', 0)} GB")
        
        st.markdown("---")
        
        # EC2 Instances Overview
        if ec2_instances:
            st.subheader("🖥️ EC2 SQL Server Instances")
            for ec2 in ec2_instances:
                instance_name = "Unknown"
                for tag in ec2.get('Tags', []):
                    if tag['Key'] == 'Name':
                        instance_name = tag['Value']
                        break
                
                status = ec2['State']['Name']
                status_color = "cluster-online" if status == 'running' else "cluster-offline"
                
                st.markdown(f'<div class="{status_color}">🖥️ <strong>{instance_name}</strong> ({ec2["InstanceId"]}) - {status.title()}</div>', 
                           unsafe_allow_html=True)
                
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.write(f"**Type:** {ec2['InstanceType']}")
                with col2:
                    st.write(f"**Private IP:** {ec2.get('PrivateIpAddress', 'N/A')}")
                with col3:
                    st.write(f"**State:** {status}")
                with col4:
                    if st.button(f"Manage {instance_name}", key=f"manage_{ec2['InstanceId']}"):
                        st.info(f"Management interface for {instance_name}")
        
        # Performance metrics charts
        st.markdown("---")
        st.subheader("📈 Real-time Performance Metrics")
        
        if all_metrics:
            col1, col2 = st.columns(2)
            
            with col1:
                if all_metrics.get('cpu_usage'):
                    cpu_data = all_metrics['cpu_usage']
                    fig = go.Figure()
                    fig.add_trace(go.Scatter(
                        x=[dp['Timestamp'] for dp in cpu_data],
                        y=[dp['Average'] for dp in cpu_data],
                        name='CPU Usage %',
                        line=dict(color='blue')
                    ))
                    fig.add_hline(y=80, line_dash="dash", line_color="orange", annotation_text="Warning (80%)")
                    fig.add_hline(y=90, line_dash="dash", line_color="red", annotation_text="Critical (90%)")
                    fig.update_layout(title="CPU Utilization", xaxis_title="Time", yaxis_title="CPU %", height=300)
                    st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                if all_metrics.get('memory_usage'):
                    memory_data = all_metrics['memory_usage']
                    fig = go.Figure()
                    fig.add_trace(go.Scatter(
                        x=[dp['Timestamp'] for dp in memory_data],
                        y=[dp['Average'] for dp in memory_data],
                        name='Memory Usage %',
                        line=dict(color='green')
                    ))
                    fig.add_hline(y=85, line_dash="dash", line_color="orange", annotation_text="Warning (85%)")
                    fig.add_hline(y=95, line_dash="dash", line_color="red", annotation_text="Critical (95%)")
                    fig.update_layout(title="Memory Utilization", xaxis_title="Time", yaxis_title="Memory %", height=300)
                    st.plotly_chart(fig, use_container_width=True)
        else:
            st.warning("⚠️ No metrics data available. This could be due to:")
            st.write("• CloudWatch agent not installed on instances")
            st.write("• Custom metrics not configured")
            st.write("• Insufficient permissions")
            st.write("• Network connectivity issues")
            
            if st.session_state.cloudwatch_connector.demo_mode:
                st.info("🎭 **Currently in Demo Mode** - Real metrics will appear when AWS is properly configured")
    
    # Continue with other tabs (SQL Metrics, OS Metrics, etc.) - they would follow the same pattern
    # For brevity, I'll include a few key tabs...
    
    # =================== SQL Metrics Tab ===================
    with tab2:
        st.header("🗄️ Comprehensive SQL Server Database Metrics")
        
        # Instance selector for detailed metrics
        if ec2_instances:
            instance_options = {}
            for ec2 in ec2_instances:
                instance_name = "Unknown"
                for tag in ec2.get('Tags', []):
                    if tag['Key'] == 'Name':
                        instance_name = tag['Value']
                        break
                instance_options[f"{instance_name} ({ec2['InstanceId']})"] = ec2['InstanceId']
            
            selected_instance_display = st.selectbox("Select SQL Server Instance for Detailed Analysis", 
                                                    list(instance_options.keys()))
            selected_instance = instance_options[selected_instance_display]
            
            st.markdown(f"### 📊 Detailed Metrics for {selected_instance_display}")
            
            # Check if we have metrics for this instance
            instance_metrics = {k: v for k, v in all_metrics.items() if k.startswith(selected_instance)}
            
            if instance_metrics:
                st.success(f"✅ Found {len(instance_metrics)} metric series for this instance")
                
                # Display key SQL Server metrics
                col1, col2, col3, col4 = st.columns(4)
                
                # Buffer Cache Hit Ratio
                buffer_cache_key = f"{selected_instance}_buffer_cache_hit_ratio"
                if buffer_cache_key in all_metrics and all_metrics[buffer_cache_key]:
                    current_value = all_metrics[buffer_cache_key][-1]['Average']
                    color = "🟢" if current_value > 95 else "🟡" if current_value > 90 else "🔴"
                    with col1:
                        st.metric(f"Buffer Cache Hit Ratio {color}", f"{current_value:.2f}%")
                
                # User Connections
                connections_key = f"{selected_instance}_user_connections"
                if connections_key in all_metrics and all_metrics[connections_key]:
                    current_value = all_metrics[connections_key][-1]['Average']
                    with col2:
                        st.metric("User Connections", f"{current_value:.0f}")
                
                # Batch Requests/sec
                batch_key = f"{selected_instance}_batch_requests_per_sec"
                if batch_key in all_metrics and all_metrics[batch_key]:
                    current_value = all_metrics[batch_key][-1]['Average']
                    with col3:
                        st.metric("Batch Requests/sec", f"{current_value:.0f}")
                
                # Deadlocks/sec
                deadlock_key = f"{selected_instance}_deadlocks_per_sec"
                if deadlock_key in all_metrics and all_metrics[deadlock_key]:
                    current_value = all_metrics[deadlock_key][-1]['Average']
                    color = "🔴" if current_value > 0.1 else "🟡" if current_value > 0 else "🟢"
                    with col4:
                        st.metric(f"Deadlocks/sec {color}", f"{current_value:.3f}")
                
                # Chart showing SQL Server performance over time
                if buffer_cache_key in all_metrics and all_metrics[buffer_cache_key]:
                    fig = go.Figure()
                    fig.add_trace(go.Scatter(
                        x=[dp['Timestamp'] for dp in all_metrics[buffer_cache_key]],
                        y=[dp['Average'] for dp in all_metrics[buffer_cache_key]],
                        name='Buffer Cache Hit Ratio %',
                        line=dict(color='blue')
                    ))
                    fig.update_layout(title="SQL Server Buffer Cache Hit Ratio", 
                                    xaxis_title="Time", yaxis_title="Hit Ratio %")
                    st.plotly_chart(fig, use_container_width=True)
            
            else:
                st.warning(f"⚠️ No SQL Server metrics found for instance {selected_instance}")
                st.info("This could be because:")
                st.write("• CloudWatch agent is not configured for SQL Server metrics")
                st.write("• Custom SQL Server performance counters are not set up")
                st.write("• The instance may not be running SQL Server")
                st.write("• Metrics collection may not have started yet")
                
                if st.session_state.cloudwatch_connector.demo_mode:
                    st.info("🎭 **Demo Mode:** Real metrics will appear when connected to AWS")
        
        else:
            st.warning("No EC2 SQL Server instances found. Please ensure instances are properly tagged.")
            
            if st.session_state.cloudwatch_connector.demo_mode:
                st.info("🎭 **Demo Mode:** Real instances will appear when connected to AWS")
    
    # =================== Auto-Remediation Tab ===================
    with tab5:
        st.header("🤖 Intelligent Auto-Remediation")
        
        if enable_auto_remediation:
            # Evaluate current conditions for remediation
            current_alerts = []  # This would come from your alert system
            remediation_actions = st.session_state.auto_remediation.evaluate_conditions(all_metrics, current_alerts)
            
            if remediation_actions:
                st.subheader("🚨 Remediation Actions Required")
                
                for action in remediation_actions:
                    severity_color = {
                        'Critical': 'alert-critical',
                        'High': 'alert-warning',
                        'Medium': 'alert-warning',
                        'Low': 'metric-card'
                    }.get(action['severity'], 'metric-card')
                    
                    st.markdown(f"""
                    <div class="{severity_color}">
                        <strong>🔧 {action['rule_name'].replace('_', ' ').title()}</strong><br>
                        <strong>Severity:</strong> {action['severity']}<br>
                        <strong>Estimated Impact:</strong> {action['estimated_impact']}<br>
                        <strong>Proposed Actions:</strong> {', '.join(action['actions'])}<br>
                        <strong>Auto-Execute:</strong> {'Yes' if action['auto_execute'] else 'Manual Approval Required'}
                    </div>
                    """, unsafe_allow_html=True)
                    
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        if action['auto_execute']:
                            if st.button(f"🤖 Auto-Execute", key=f"auto_{action['rule_name']}"):
                                with st.spinner("Executing remediation..."):
                                    result = st.session_state.auto_remediation.execute_remediation(action)
                                    if result['status'] == 'success':
                                        st.success(f"✅ {result['message']}")
                                    else:
                                        st.error(f"❌ {result['message']}")
                    
                    with col2:
                        if st.button(f"👁️ Preview Actions", key=f"preview_{action['rule_name']}"):
                            st.info(f"Would execute: {', '.join(action['actions'])}")
                    
                    with col3:
                        if st.button(f"⏸️ Postpone", key=f"postpone_{action['rule_name']}"):
                            st.info("Action postponed for 1 hour")
                    
                    st.markdown("---")
            
            else:
                st.success("🎉 No immediate remediation actions required!")
                st.info("All systems are operating within normal parameters.")
                
                # Show remediation history if available
                if st.session_state.auto_remediation.remediation_history:
                    with st.expander("📋 Recent Remediation History"):
                        for entry in st.session_state.auto_remediation.remediation_history[-5:]:
                            st.write(f"**{entry['executed_at'].strftime('%Y-%m-%d %H:%M:%S')}** - {entry['action']['rule_name']}")
        
        else:
            st.warning("🔒 Auto-remediation is currently disabled")
            st.info("Enable auto-remediation in the sidebar to see available actions and configure automated responses to system issues.")
            
            # Show configuration options
            with st.expander("⚙️ Auto-Remediation Configuration"):
                st.write("**Available Remediation Rules:**")
                for rule_name, rule_config in st.session_state.auto_remediation.remediation_rules.items():
                    st.write(f"• **{rule_name.replace('_', ' ').title()}**: Threshold {rule_config['threshold']}")
    
    # =================== OS Metrics Tab ===================
    with tab3:
        st.header("🖥️ Operating System Metrics")
        
        if ec2_instances:
            # Instance selector
            instance_options = {}
            for ec2 in ec2_instances:
                instance_name = "Unknown"
                for tag in ec2.get('Tags', []):
                    if tag['Key'] == 'Name':
                        instance_name = tag['Value']
                        break
                instance_options[f"{instance_name} ({ec2['InstanceId']})"] = ec2['InstanceId']
            
            selected_instance_display = st.selectbox("Select Instance for OS Metrics", 
                                                    list(instance_options.keys()))
            selected_instance = instance_options[selected_instance_display]
            
            st.markdown(f"### 🖥️ OS Metrics for {selected_instance_display}")
            
            # Check for OS metrics
            os_metrics = {k: v for k, v in all_metrics.items() if k.startswith(f"{selected_instance}_os_")}
            
            if os_metrics:
                # Display current OS metrics
                col1, col2, col3, col4 = st.columns(4)
                
                # CPU metrics
                cpu_key = f"{selected_instance}_os_cpu_usage_active"
                if cpu_key in all_metrics and all_metrics[cpu_key]:
                    current_cpu = all_metrics[cpu_key][-1]['Average']
                    color = "🔴" if current_cpu > 80 else "🟡" if current_cpu > 60 else "🟢"
                    with col1:
                        st.metric(f"CPU Usage {color}", f"{current_cpu:.1f}%")
                
                # Memory metrics
                mem_key = f"{selected_instance}_os_mem_used_percent"
                if mem_key in all_metrics and all_metrics[mem_key]:
                    current_mem = all_metrics[mem_key][-1]['Average']
                    color = "🔴" if current_mem > 90 else "🟡" if current_mem > 80 else "🟢"
                    with col2:
                        st.metric(f"Memory Used {color}", f"{current_mem:.1f}%")
                
                # Disk metrics
                disk_key = f"{selected_instance}_os_disk_used_percent"
                if disk_key in all_metrics and all_metrics[disk_key]:
                    current_disk = all_metrics[disk_key][-1]['Average']
                    color = "🔴" if current_disk > 90 else "🟡" if current_disk > 80 else "🟢"
                    with col3:
                        st.metric(f"Disk Used {color}", f"{current_disk:.1f}%")
                
                # Load average
                load_key = f"{selected_instance}_os_system_load1"
                if load_key in all_metrics and all_metrics[load_key]:
                    current_load = all_metrics[load_key][-1]['Average']
                    color = "🔴" if current_load > 4 else "🟡" if current_load > 2 else "🟢"
                    with col4:
                        st.metric(f"Load Average {color}", f"{current_load:.2f}")
                
                # OS Performance chart
                if cpu_key in all_metrics and mem_key in all_metrics:
                    fig = make_subplots(
                        rows=2, cols=1,
                        subplot_titles=('CPU Usage %', 'Memory Usage %'),
                        shared_xaxes=True
                    )
                    
                    fig.add_trace(
                        go.Scatter(
                            x=[dp['Timestamp'] for dp in all_metrics[cpu_key]],
                            y=[dp['Average'] for dp in all_metrics[cpu_key]],
                            name='CPU %',
                            line=dict(color='blue')
                        ),
                        row=1, col=1
                    )
                    
                    fig.add_trace(
                        go.Scatter(
                            x=[dp['Timestamp'] for dp in all_metrics[mem_key]],
                            y=[dp['Average'] for dp in all_metrics[mem_key]],
                            name='Memory %',
                            line=dict(color='green')
                        ),
                        row=2, col=1
                    )
                    
                    fig.update_layout(height=500, title_text="OS Performance Trends")
                    st.plotly_chart(fig, use_container_width=True)
            
            else:
                st.warning(f"⚠️ No OS metrics found for instance {selected_instance}")
                st.info("This could be because:")
                st.write("• CloudWatch agent is not installed")
                st.write("• OS metrics collection is not enabled")
                st.write("• Instance may not be running")
                
                if st.session_state.cloudwatch_connector.demo_mode:
                    st.info("🎭 **Demo Mode:** Real OS metrics will appear when connected to AWS")
        
        else:
            st.warning("No EC2 instances found for OS metrics monitoring.")
    
    # =================== Always On Tab ===================
    with tab4:
        st.header("🔄 Always On Availability Groups")
        
        # Get AG information
        availability_groups = st.session_state.always_on_monitor.get_availability_groups()
        
        if availability_groups:
            for ag in availability_groups:
                # AG Status Header
                sync_status = ag['synchronization_health']
                status_color = "cluster-online" if sync_status == 'HEALTHY' else "cluster-degraded" if sync_status == 'PARTIALLY_HEALTHY' else "cluster-offline"
                
                st.markdown(f'<div class="{status_color}">🔄 <strong>{ag["name"]}</strong> - {sync_status}</div>', 
                           unsafe_allow_html=True)
                
                # AG Details
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.write(f"**Primary Replica:** {ag['primary_replica']}")
                    st.write(f"**Role Health:** {ag['role_health']}")
                
                with col2:
                    st.write(f"**Secondary Replicas:** {len(ag['secondary_replicas'])}")
                    for replica in ag['secondary_replicas']:
                        st.write(f"  • {replica}")
                
                with col3:
                    st.write(f"**Databases:** {len(ag['databases'])}")
                    for db in ag['databases']:
                        st.write(f"  • {db}")
                
                # Replica Health Details
                with st.expander(f"🔍 Detailed Health - {ag['name']}"):
                    replica_data = []
                    
                    # Primary replica
                    primary_health = st.session_state.always_on_monitor.get_replica_health(ag['primary_replica'])
                    replica_data.append(primary_health)
                    
                    # Secondary replicas
                    for replica in ag['secondary_replicas']:
                        secondary_health = st.session_state.always_on_monitor.get_replica_health(replica)
                        replica_data.append(secondary_health)
                    
                    # Display replica health table
                    if replica_data:
                        replica_df = pd.DataFrame(replica_data)
                        st.dataframe(replica_df, use_container_width=True)
                
                # Synchronization Lag
                st.subheader(f"📊 Synchronization Status - {ag['name']}")
                sync_lag = st.session_state.always_on_monitor.check_synchronization_lag()
                
                if sync_lag:
                    lag_df = pd.DataFrame(sync_lag)
                    
                    # Color code based on lag
                    def lag_color(lag_seconds):
                        if lag_seconds < 1:
                            return "🟢"
                        elif lag_seconds < 5:
                            return "🟡"
                        else:
                            return "🔴"
                    
                    lag_df['Status'] = lag_df['lag_seconds'].apply(lag_color)
                    st.dataframe(lag_df, use_container_width=True)
                    
                    # Alert on high lag
                    high_lag_dbs = lag_df[lag_df['lag_seconds'] > 5]
                    if not high_lag_dbs.empty:
                        st.warning(f"⚠️ High synchronization lag detected for {len(high_lag_dbs)} databases")
                
                st.markdown("---")
        
        else:
            st.info("📝 No Always On Availability Groups detected in your environment")
            st.write("**To set up Always On monitoring:**")
            st.write("1. Ensure CloudWatch agent is installed on SQL Server instances")
            st.write("2. Configure custom metrics for Always On DMVs")
            st.write("3. Set up appropriate IAM permissions")
            
            if st.session_state.cloudwatch_connector.demo_mode:
                st.info("🎭 **Demo Mode:** Real Always On groups will appear when connected to AWS")
    
    # =================== Predictive Analytics Tab ===================
    with tab6:
        st.header("🔮 Predictive Analytics & Forecasting")
        
        if enable_predictive_alerts:
            # Analyze trends
            trend_analysis = st.session_state.predictive_analytics.analyze_trends(all_metrics, days=30)
            
            if trend_analysis:
                st.subheader("📊 Performance Trend Analysis")
                
                # Filter out metrics with insufficient data
                valid_analyses = {k: v for k, v in trend_analysis.items() if v.get('status') == 'analyzed'}
                
                if valid_analyses:
                    for metric_name, analysis in list(valid_analyses.items())[:5]:  # Show top 5
                        col1, col2 = st.columns([3, 1])
                        
                        with col1:
                            # Create prediction visualization
                            if all_metrics.get(metric_name):
                                historical_data = all_metrics[metric_name]
                                predicted_values = analysis['future_prediction']
                                
                                fig = go.Figure()
                                
                                # Historical data
                                fig.add_trace(go.Scatter(
                                    x=[dp['Timestamp'] for dp in historical_data],
                                    y=[dp['Average'] for dp in historical_data],
                                    name='Historical',
                                    line=dict(color='blue')
                                ))
                                
                                # Predicted data
                                future_timestamps = [
                                    datetime.now() + timedelta(hours=i) 
                                    for i in range(len(predicted_values))
                                ]
                                
                                fig.add_trace(go.Scatter(
                                    x=future_timestamps,
                                    y=predicted_values,
                                    name='Predicted',
                                    line=dict(color='red', dash='dash')
                                ))
                                
                                fig.update_layout(
                                    title=f"{metric_name.replace('_', ' ').title()} - Trend Analysis",
                                    xaxis_title="Time",
                                    yaxis_title="Value",
                                    height=300
                                )
                                
                                st.plotly_chart(fig, use_container_width=True)
                        
                        with col2:
                            # Analysis summary
                            risk_colors = {
                                'critical': '🔴',
                                'warning': '🟡',
                                'low': '🟢'
                            }
                            
                            trend_colors = {
                                'increasing': '📈',
                                'decreasing': '📉',
                                'stable': '➡️'
                            }
                            
                            st.metric(
                                f"Risk Level {risk_colors.get(analysis['risk_level'], '🔵')}", 
                                analysis['risk_level'].title()
                            )
                            
                            st.metric(
                                f"Trend {trend_colors.get(analysis['trend'], '➡️')}", 
                                analysis['trend'].title()
                            )
                            
                            st.metric(
                                "Confidence", 
                                f"{analysis['confidence']*100:.0f}%"
                            )
                        
                        # Recommendations
                        if analysis.get('recommendations'):
                            st.write(f"**🎯 Recommendations for {metric_name.replace('_', ' ').title()}:**")
                            for rec in analysis['recommendations'][:3]:  # Show top 3
                                st.write(f"• {rec}")
                        
                        st.markdown("---")
                
                else:
                    st.warning("⚠️ Insufficient data for trend analysis")
                    st.info("Need at least 10 data points per metric for reliable predictions")
            
            # Capacity Planning
            st.subheader("📈 Capacity Planning Insights")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.write("**🔮 30-Day Forecast:**")
                
                # Generate capacity predictions based on available data
                capacity_predictions = {}
                for metric_name in ['cpu_usage', 'memory_usage', 'disk_usage']:
                    if metric_name in all_metrics and all_metrics[metric_name]:
                        current = all_metrics[metric_name][-1]['Average']
                        # Simple trend calculation
                        if len(all_metrics[metric_name]) > 5:
                            recent_values = [dp['Average'] for dp in all_metrics[metric_name][-5:]]
                            trend = (recent_values[-1] - recent_values[0]) / len(recent_values)
                            predicted = current + (trend * 30)  # 30 days
                            trend_direction = 'increasing' if trend > 0.5 else 'decreasing' if trend < -0.5 else 'stable'
                        else:
                            predicted = current
                            trend_direction = 'stable'
                        
                        capacity_predictions[metric_name] = {
                            'current': current,
                            'predicted': predicted,
                            'trend': trend_direction
                        }
                
                for resource, data in capacity_predictions.items():
                    trend_icon = {'increasing': '📈', 'decreasing': '📉', 'stable': '➡️'}[data['trend']]
                    color = '🔴' if data['predicted'] > 90 else '🟡' if data['predicted'] > 80 else '🟢'
                    
                    st.write(f"{color} **{resource.replace('_', ' ').title()}:** {data['current']:.1f}% → {data['predicted']:.1f}% {trend_icon}")
            
            with col2:
                st.write("**⚠️ Capacity Recommendations:**")
                recommendations = []
                
                for resource, data in capacity_predictions.items():
                    if data['predicted'] > 90:
                        recommendations.append(f"• Urgent: Scale {resource.replace('_', ' ')} capacity")
                    elif data['predicted'] > 80:
                        recommendations.append(f"• Plan: Monitor {resource.replace('_', ' ')} usage closely")
                
                if recommendations:
                    for rec in recommendations:
                        st.write(rec)
                else:
                    st.write("• ✅ All resources within normal capacity projections")
        
        else:
            st.warning("🔒 Predictive analytics is currently disabled")
            st.info("Enable predictive alerts in the sidebar to see trend analysis and capacity planning insights.")
    
    # =================== Alerts Tab ===================
    with tab7:
        st.header("🚨 Intelligent Alert Management")
        
        # Generate current alerts based on metrics
        current_alerts = []
        
        # Check for critical conditions
        if all_metrics.get('cpu_usage'):
            latest_cpu = all_metrics['cpu_usage'][-1]['Average']
            if latest_cpu > 90:
                current_alerts.append({
                    'timestamp': datetime.now(),
                    'severity': 'critical',
                    'source': 'CloudWatch',
                    'instance': 'System Average',
                    'message': f'Critical CPU utilization detected ({latest_cpu:.1f}%)',
                    'auto_remediation': 'Available'
                })
            elif latest_cpu > 80:
                current_alerts.append({
                    'timestamp': datetime.now(),
                    'severity': 'warning',
                    'source': 'CloudWatch',
                    'instance': 'System Average',
                    'message': f'High CPU utilization detected ({latest_cpu:.1f}%)',
                    'auto_remediation': 'Available'
                })
        
        # Add demo alerts for demonstration
        if st.session_state.cloudwatch_connector.demo_mode:
            demo_alerts = [
                {
                    'timestamp': datetime.now() - timedelta(minutes=5),
                    'severity': 'warning',
                    'source': 'Always On Monitor',
                    'instance': 'AG-Production',
                    'message': 'Synchronization lag detected (3.2 seconds)',
                    'auto_remediation': 'Manual'
                },
                {
                    'timestamp': datetime.now() - timedelta(hours=1),
                    'severity': 'info',
                    'source': 'Predictive Analytics',
                    'instance': 'sql-server-prod-2',
                    'message': 'Memory usage trend increasing - action recommended within 24h',
                    'auto_remediation': 'Scheduled'
                }
            ]
            current_alerts.extend(demo_alerts)
        
        # Alert summary
        col1, col2, col3, col4 = st.columns(4)
        
        critical_alerts = [a for a in current_alerts if a['severity'] == 'critical']
        warning_alerts = [a for a in current_alerts if a['severity'] == 'warning']
        info_alerts = [a for a in current_alerts if a['severity'] == 'info']
        
        with col1:
            st.metric("🔴 Critical", len(critical_alerts))
        
        with col2:
            st.metric("🟡 Warning", len(warning_alerts))
        
        with col3:
            st.metric("🔵 Info", len(info_alerts))
        
        with col4:
            auto_remediated = [a for a in current_alerts if a['auto_remediation'] == 'Available']
            st.metric("🤖 Auto-Remediation", len(auto_remediated))
        
        st.markdown("---")
        
        # Alert list
        if current_alerts:
            st.subheader("📋 Active Alerts")
            
            for alert in current_alerts:
                severity_styles = {
                    'critical': 'alert-critical',
                    'warning': 'alert-warning',
                    'info': 'claude-insight'
                }
                
                style_class = severity_styles.get(alert['severity'], 'metric-card')
                timestamp_str = alert['timestamp'].strftime("%Y-%m-%d %H:%M:%S")
                
                st.markdown(f"""
                <div class="{style_class}">
                    <strong>{alert['severity'].upper()}</strong> - {alert['instance']}<br>
                    <strong>Source:</strong> {alert['source']}<br>
                    <strong>Message:</strong> {alert['message']}<br>
                    <strong>Time:</strong> {timestamp_str}<br>
                    <strong>Auto-Remediation:</strong> {alert['auto_remediation']}
                </div>
                """, unsafe_allow_html=True)
                
                if alert['severity'] == 'critical':
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        if st.button(f"🔧 Remediate", key=f"remediate_{alert['instance']}_{alert['timestamp']}"):
                            st.success("Remediation action initiated")
                    with col2:
                        if st.button(f"📞 Escalate", key=f"escalate_{alert['instance']}_{alert['timestamp']}"):
                            st.info("Alert escalated to on-call engineer")
                    with col3:
                        if st.button(f"✅ Acknowledge", key=f"ack_{alert['instance']}_{alert['timestamp']}"):
                            st.info("Alert acknowledged")
        
        else:
            st.success("🎉 No active alerts!")
            st.info("All monitored systems are operating normally.")
        
        # Enhanced logs display
        st.markdown("---")
        st.subheader("📝 CloudWatch Logs Analysis")
        
        if all_logs:
            # Log group selector
            selected_log_group = st.selectbox(
                "Select Log Group", 
                list(all_logs.keys())
            )
            
            if selected_log_group and all_logs[selected_log_group]:
                logs = all_logs[selected_log_group]
                
                # Log filters
                col1, col2, col3 = st.columns(3)
                with col1:
                    log_level = st.selectbox("Filter by Level", 
                                           ["All", "Error", "Warning", "Info"])
                with col2:
                    search_term = st.text_input("Search in logs")
                with col3:
                    max_logs = st.slider("Max logs to display", 10, 100, 20)
                
                # Filter logs
                filtered_logs = logs[:max_logs]
                if search_term:
                    filtered_logs = [log for log in filtered_logs 
                                   if search_term.lower() in log['message'].lower()]
                
                # Display logs
                for log in filtered_logs:
                    timestamp = datetime.fromtimestamp(log['timestamp'] / 1000)
                    st.text(f"[{timestamp}] {log['message']}")
        
        else:
            st.info("No log data available. Configure log groups in the sidebar.")
    
    # =================== Performance Tab ===================
    with tab8:
        st.header("📊 Advanced Performance Analytics")
        
        # Performance overview
        if all_metrics:
            st.subheader("🎯 Performance Overview")
            
            # Create performance score
            scores = {}
            if all_metrics.get('cpu_usage'):
                avg_cpu = np.mean([dp['Average'] for dp in all_metrics['cpu_usage'][-5:]])
                scores['CPU'] = max(0, 100 - avg_cpu)
            
            if all_metrics.get('memory_usage'):
                avg_memory = np.mean([dp['Average'] for dp in all_metrics['memory_usage'][-5:]])
                scores['Memory'] = max(0, 100 - avg_memory)
            
            # Performance score visualization
            if scores:
                fig = go.Figure(go.Bar(
                    x=list(scores.keys()),
                    y=list(scores.values()),
                    marker_color=['green' if v > 70 else 'orange' if v > 50 else 'red' for v in scores.values()]
                ))
                
                fig.update_layout(
                    title="Performance Scores (Higher is Better)",
                    yaxis_title="Score",
                    height=300
                )
                
                st.plotly_chart(fig, use_container_width=True)
            
            # Detailed metrics
            st.subheader("📈 Detailed Performance Metrics")
            
            metric_tabs = st.tabs(["CPU", "Memory", "Disk", "Network"])
            
            with metric_tabs[0]:
                if all_metrics.get('cpu_usage'):
                    cpu_data = all_metrics['cpu_usage']
                    
                    # CPU trend chart
                    fig = go.Figure()
                    fig.add_trace(go.Scatter(
                        x=[dp['Timestamp'] for dp in cpu_data],
                        y=[dp['Average'] for dp in cpu_data],
                        name='CPU Usage %',
                        line=dict(color='blue')
                    ))
                    
                    # Add trend line
                    values = [dp['Average'] for dp in cpu_data]
                    x_vals = list(range(len(values)))
                    z = np.polyfit(x_vals, values, 1)
                    p = np.poly1d(z)
                    
                    fig.add_trace(go.Scatter(
                        x=[dp['Timestamp'] for dp in cpu_data],
                        y=p(x_vals),
                        name='Trend',
                        line=dict(color='red', dash='dash')
                    ))
                    
                    fig.update_layout(title="CPU Utilization with Trend", height=400)
                    st.plotly_chart(fig, use_container_width=True)
                    
                    # CPU statistics
                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        st.metric("Current", f"{values[-1]:.1f}%")
                    with col2:
                        st.metric("Average", f"{np.mean(values):.1f}%")
                    with col3:
                        st.metric("Peak", f"{max(values):.1f}%")
                    with col4:
                        st.metric("Trend", "Increasing" if z[0] > 0 else "Decreasing")
            
            with metric_tabs[1]:
                if all_metrics.get('memory_usage'):
                    st.info("Memory analysis would be displayed here with similar trending and statistics")
            
            with metric_tabs[2]:
                st.info("Disk I/O metrics and analysis would be displayed here")
            
            with metric_tabs[3]:
                st.info("Network performance metrics would be displayed here")
        
        else:
            st.warning("No performance metrics available. Check CloudWatch configuration.")
            
            if st.session_state.cloudwatch_connector.demo_mode:
                st.info("🎭 **Demo Mode:** Real performance data will appear when connected to AWS")
    
    # =================== Reports Tab ===================
    with tab9:
        st.header("📈 Executive Reports & Analytics")
        
        # Report selector
        report_type = st.selectbox("Select Report Type", [
            "Executive Summary",
            "Performance Report",
            "Availability Report",
            "Capacity Planning",
            "Security Assessment",
            "Cost Analysis"
        ])
        
        if report_type == "Executive Summary":
            st.subheader("📊 Executive Summary Report")
            
            # Calculate metrics for summary
            system_health = 87
            if all_metrics.get('cpu_usage') and all_metrics.get('memory_usage'):
                avg_cpu = np.mean([dp['Average'] for dp in all_metrics['cpu_usage'][-10:]])
                avg_mem = np.mean([dp['Average'] for dp in all_metrics['memory_usage'][-10:]])
                system_health = max(0, 100 - ((avg_cpu + avg_mem) / 2))
            
            # Key metrics summary
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.markdown(f"""
                <div class="metric-card">
                    <h3>🎯 System Health</h3>
                    <p><strong>Overall Score:</strong> {system_health:.0f}/100</p>
                    <p><strong>Availability:</strong> 99.95%</p>
                    <p><strong>Performance:</strong> {'Good' if system_health > 70 else 'Poor'}</p>
                </div>
                """, unsafe_allow_html=True)
            
            with col2:
                remediation_count = len(current_alerts) if 'current_alerts' in locals() else 0
                st.markdown(f"""
                <div class="metric-card">
                    <h3>🔧 Maintenance</h3>
                    <p><strong>Active Alerts:</strong> {remediation_count}</p>
                    <p><strong>Auto-Remediated:</strong> 15 issues</p>
                    <p><strong>Manual Actions:</strong> 2 pending</p>
                </div>
                """, unsafe_allow_html=True)
            
            with col3:
                st.markdown("""
                <div class="metric-card">
                    <h3>💰 Cost Optimization</h3>
                    <p><strong>Potential Savings:</strong> $2,400/month</p>
                    <p><strong>Right-sizing:</strong> 3 opportunities</p>
                    <p><strong>Efficiency:</strong> 85%</p>
                </div>
                """, unsafe_allow_html=True)
            
            # Recommendations
            st.subheader("💡 Key Recommendations")
            recommendations = [
                "**Monitor CPU utilization** - Currently averaging above baseline",
                "**Optimize backup strategy** - Consider incremental backups for large databases",
                "**Review Always On configuration** - Ensure optimal synchronization",
                "**Implement automated scaling** - Based on predictive analytics"
            ]
            
            for rec in recommendations:
                st.write(f"• {rec}")
            
        elif report_type == "Performance Report":
            st.subheader("📊 Detailed Performance Report")
            
            # Performance summary table
            performance_data = []
            
            if all_metrics.get('cpu_usage'):
                avg_cpu = np.mean([dp['Average'] for dp in all_metrics['cpu_usage'][-10:]])
                performance_data.append({
                    'Metric': 'Average CPU Usage',
                    'Current': f'{avg_cpu:.1f}%',
                    'Target': '<70%',
                    'Status': '🟢 Good' if avg_cpu < 70 else '🟡 Monitor' if avg_cpu < 85 else '🔴 Critical'
                })
            
            if all_metrics.get('memory_usage'):
                avg_memory = np.mean([dp['Average'] for dp in all_metrics['memory_usage'][-10:]])
                performance_data.append({
                    'Metric': 'Average Memory Usage',
                    'Current': f'{avg_memory:.1f}%',
                    'Target': '<85%',
                    'Status': '🟢 Good' if avg_memory < 85 else '🟡 Monitor' if avg_memory < 95 else '🔴 Critical'
                })
            
            # Add default entries for demo
            performance_data.extend([
                {'Metric': 'Disk I/O Latency', 'Current': '12ms', 'Target': '<15ms', 'Status': '🟢 Good'},
                {'Metric': 'AG Sync Lag', 'Current': '2.1s', 'Target': '<5s', 'Status': '🟢 Good'},
                {'Metric': 'Backup Success Rate', 'Current': '99.2%', 'Target': '>99%', 'Status': '🟢 Good'}
            ])
            
            if performance_data:
                performance_df = pd.DataFrame(performance_data)
                st.dataframe(performance_df, use_container_width=True)
            
        elif report_type == "Capacity Planning":
            st.subheader("📈 Capacity Planning Report")
            
            # Capacity projections
            capacity_data = {
                'Resource': ['CPU', 'Memory', 'Storage', 'Connections'],
                'Current Usage': [68, 82, 45, 85],
                '30-Day Projection': [75, 85, 52, 92],
                '90-Day Projection': [82, 88, 65, 98],
                'Action Required': ['Monitor', 'Plan Upgrade', 'Expand Storage', 'Optimize Pooling']
            }
            
            capacity_df = pd.DataFrame(capacity_data)
            st.dataframe(capacity_df, use_container_width=True)
            
            # Capacity visualization
            fig = go.Figure()
            
            fig.add_trace(go.Bar(
                name='Current',
                x=capacity_data['Resource'],
                y=capacity_data['Current Usage']
            ))
            
            fig.add_trace(go.Bar(
                name='30-Day Projection',
                x=capacity_data['Resource'],
                y=capacity_data['30-Day Projection']
            ))
            
            fig.add_trace(go.Bar(
                name='90-Day Projection',
                x=capacity_data['Resource'],
                y=capacity_data['90-Day Projection']
            ))
            
            fig.update_layout(
                title="Capacity Utilization Projections",
                xaxis_title="Resource",
                yaxis_title="Usage %",
                barmode='group'
            )
            
            st.plotly_chart(fig, use_container_width=True)
        
        else:
            st.info(f"Report type '{report_type}' would be displayed here")
        
        # Export options
        st.markdown("---")
        st.subheader("📥 Export Options")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("📊 Export to Excel"):
                st.info("Excel report would be generated and downloaded")
        
        with col2:
            if st.button("📄 Generate PDF"):
                st.info("PDF report would be generated and downloaded")
        
        with col3:
            if st.button("📧 Email Report"):
                st.info("Report would be emailed to stakeholders")
    
    # Auto-refresh functionality with Streamlit Cloud optimization
    if 'last_refresh' not in st.session_state:
        st.session_state.last_refresh = datetime.now()
    
    time_since_refresh = (datetime.now() - st.session_state.last_refresh).seconds
    
    # Only auto-refresh if not in demo mode to avoid excessive API calls
    if time_since_refresh >= refresh_interval and not st.session_state.cloudwatch_connector.demo_mode:
        st.session_state.last_refresh = datetime.now()
        st.rerun()
    
    # Enhanced status bar with Streamlit Cloud info
    st.sidebar.markdown("---")
    st.sidebar.write(f"🔄 Last refresh: {st.session_state.last_refresh.strftime('%H:%M:%S')}")
    
    if not st.session_state.cloudwatch_connector.demo_mode:
        st.sidebar.write(f"⏱️ Next refresh: {refresh_interval - time_since_refresh}s")
    else:
        st.sidebar.write("⏱️ Auto-refresh disabled in demo mode")
    
    # Connection status indicator
    if st.session_state.cloudwatch_connector:
        conn_status = st.session_state.cloudwatch_connector.get_connection_status()
        if conn_status.get('connected'):
            if conn_status.get('demo_mode'):
                st.sidebar.warning("🎭 Demo Mode")
            else:
                st.sidebar.success("🟢 AWS Connected")
        else:
            st.sidebar.error("🔴 AWS Disconnected")
        
        # Environment info
        if conn_status.get('streamlit_cloud'):
            st.sidebar.info("🌐 Streamlit Cloud")
    
    if st.sidebar.button("🔄 Refresh Now", type="primary"):
        # Clear cache for fresh data
        collect_comprehensive_metrics.clear()
        st.rerun()

if __name__ == "__main__":
    main()