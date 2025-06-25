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

# Try to import required AWS libraries
try:
    import boto3
    from botocore.exceptions import ClientError, BotoCoreError
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
</style>
""", unsafe_allow_html=True)

# =================== AWS CloudWatch Integration ===================
class ImprovedAWSCloudWatchConnector:
    def __init__(self, aws_config: Dict):
        """Initialize AWS CloudWatch connections with improved error handling"""
        self.aws_config = aws_config
        self.demo_mode = True  # Start in demo mode
        self.connection_status = "not_tested"
        self.connection_error = None
        
        # Initialize clients as None
        self.session = None
        self.cloudwatch = None
        self.logs = None
        self.rds = None
        self.ec2 = None
        self.ssm = None
        self.lambda_client = None
        
        # Try to initialize AWS clients
        self._initialize_aws_clients()
    
    def _initialize_aws_clients(self):
        """Initialize AWS clients with comprehensive error handling"""
        try:
            # Method 1: Try with provided credentials
            if self.aws_config.get('access_key') and self.aws_config.get('secret_key'):
                self.session = boto3.Session(
                    aws_access_key_id=self.aws_config.get('access_key'),
                    aws_secret_access_key=self.aws_config.get('secret_key'),
                    region_name=self.aws_config.get('region', 'us-east-1')
                )
                st.info("🔑 Using provided AWS credentials")
            
            # Method 2: Try with environment variables or AWS CLI config
            else:
                self.session = boto3.Session(
                    region_name=self.aws_config.get('region', 'us-east-1')
                )
                st.info("🔑 Using default AWS credential chain")
            
            # Initialize all AWS service clients
            self.cloudwatch = self.session.client('cloudwatch')
            self.logs = self.session.client('logs')
            self.rds = self.session.client('rds')
            self.ec2 = self.session.client('ec2')
            self.ssm = self.session.client('ssm')
            self.lambda_client = self.session.client('lambda')
            
            self.connection_status = "initialized"
            
        except NoCredentialsError:
            self.connection_error = "No AWS credentials found"
            st.error("❌ No AWS credentials found")
            self._show_credential_help()
            
        except PartialCredentialsError:
            self.connection_error = "Incomplete AWS credentials"
            st.error("❌ Incomplete AWS credentials")
            self._show_credential_help()
            
        except Exception as e:
            self.connection_error = str(e)
            st.error(f"❌ Failed to initialize AWS clients: {str(e)}")
    
    def test_connection(self) -> Tuple[bool, str]:
        """Test AWS connection with detailed error reporting"""
        if self.connection_status == "not_tested" or self.connection_error:
            return False, self.connection_error or "Not initialized"
        
        try:
            # Test 1: Basic credential validation
            sts = self.session.client('sts')
            identity = sts.get_caller_identity()
            
            # Test 2: CloudWatch access (the failing operation)
            response = self.cloudwatch.list_metrics(MaxRecords=1)
            
            self.demo_mode = False
            self.connection_status = "connected"
            
            return True, f"Connected as {identity.get('Arn', 'Unknown')}"
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            
            # Handle specific AWS errors
            if error_code == 'InvalidClientTokenId':
                return False, "Invalid AWS Access Key ID"
            elif error_code == 'SignatureDoesNotMatch':
                return False, "Invalid AWS Secret Access Key"
            elif error_code == 'TokenRefreshRequired':
                return False, "AWS credentials have expired"
            elif error_code == 'AccessDenied':
                return False, f"Access denied: {error_message}"
            elif error_code == 'UnauthorizedOperation':
                return False, f"Insufficient permissions: {error_message}"
            else:
                return False, f"AWS Error: {error_code} - {error_message}"
                
        except Exception as e:
            return False, f"Connection test failed: {str(e)}"
    
    def _show_credential_help(self):
        """Show credential configuration help"""
        st.markdown("""
        ### 🔧 AWS Credentials Setup Guide
        
        #### Option 1: Environment Variables (Recommended)
        ```bash
        export AWS_ACCESS_KEY_ID=your_access_key
        export AWS_SECRET_ACCESS_KEY=your_secret_key
        export AWS_DEFAULT_REGION=us-east-1
        ```
        
        #### Option 2: AWS CLI Configuration
        ```bash
        aws configure
        ```
        
        #### Option 3: Provide in Sidebar
        Enter your AWS credentials in the sidebar configuration.
        
        #### Required Permissions
        Your AWS user/role needs these permissions:
        - CloudWatch: ListMetrics, GetMetricStatistics, PutMetricData
        - CloudWatch Logs: DescribeLogGroups, FilterLogEvents
        - EC2: DescribeInstances
        - RDS: DescribeDBInstances
        - Systems Manager: DescribeInstanceInformation, SendCommand
        """)
    
    def get_connection_status_display(self):
        """Get formatted connection status for display"""
        if self.demo_mode:
            return "🎭 Demo Mode", "warning"
        elif self.connection_status == "connected":
            return "✅ Connected", "success"
        elif self.connection_error:
            return f"❌ {self.connection_error}", "error"
        else:
            return "🔄 Connecting...", "info"
    
    def diagnose_connection_issues(self):
        """Comprehensive connection diagnosis"""
        st.subheader("🔍 AWS Connection Diagnosis")
        
        # Check 1: Credential sources
        st.write("**1. Checking credential sources:**")
        
        # Check environment variables
        import os
        if os.getenv('AWS_ACCESS_KEY_ID'):
            st.success("✅ AWS_ACCESS_KEY_ID environment variable found")
        else:
            st.warning("⚠️ AWS_ACCESS_KEY_ID environment variable not found")
        
        if os.getenv('AWS_SECRET_ACCESS_KEY'):
            st.success("✅ AWS_SECRET_ACCESS_KEY environment variable found")
        else:
            st.warning("⚠️ AWS_SECRET_ACCESS_KEY environment variable not found")
        
        # Check AWS credentials file
        aws_creds_path = os.path.expanduser('~/.aws/credentials')
        if os.path.exists(aws_creds_path):
            st.success("✅ AWS credentials file found")
        else:
            st.warning("⚠️ AWS credentials file not found")
        
        # Check 2: Test basic AWS operations
        st.write("**2. Testing AWS operations:**")
        
        if self.session:
            try:
                sts = self.session.client('sts')
                identity = sts.get_caller_identity()
                st.success(f"✅ Basic AWS connection successful")
                st.info(f"Account: {identity['Account']}, User: {identity['Arn']}")
            except Exception as e:
                st.error(f"❌ Basic AWS connection failed: {str(e)}")
        
        # Check 3: Service-specific permissions
        st.write("**3. Testing service permissions:**")
        
        services_to_test = [
            ('CloudWatch', self.cloudwatch, 'list_metrics', {}),
            ('CloudWatch Logs', self.logs, 'describe_log_groups', {'limit': 1}),
            ('EC2', self.ec2, 'describe_instances', {'MaxResults': 1}),
            ('RDS', self.rds, 'describe_db_instances', {'MaxRecords': 1})
        ]
        
        for service_name, client, method_name, params in services_to_test:
            if client:
                try:
                    method = getattr(client, method_name)
                    method(**params)
                    st.success(f"✅ {service_name} permissions OK")
                except ClientError as e:
                    st.error(f"❌ {service_name} permission error: {e.response['Error']['Code']}")
                except Exception as e:
                    st.error(f"❌ {service_name} error: {str(e)}")
            else:
                st.warning(f"⚠️ {service_name} client not initialized")
    
    def show_required_iam_policy(self):
        """Display the required IAM policy"""
        st.subheader("📋 Required IAM Policy")
        
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "cloudwatch:GetMetricStatistics",
                        "cloudwatch:ListMetrics",
                        "cloudwatch:GetMetricData",
                        "cloudwatch:PutMetricData",
                        "logs:DescribeLogGroups",
                        "logs:FilterLogEvents",
                        "logs:GetLogEvents",
                        "ec2:DescribeInstances",
                        "ec2:DescribeInstanceStatus",
                        "rds:DescribeDBInstances",
                        "rds:DescribeDBClusters",
                        "ssm:DescribeInstanceInformation",
                        "ssm:SendCommand",
                        "sts:GetCallerIdentity",
                        "iam:ListAccountAliases"
                    ],
                    "Resource": "*"
                }
            ]
        }
        
        st.code(json.dumps(policy, indent=2), language='json')
        st.info("💡 Apply this policy to your IAM user or role for full functionality")

    # Example usage in your Streamlit app
    def enhanced_aws_setup():
        """Enhanced AWS setup with better error handling"""
        
        # In your sidebar configuration section, replace the existing AWS setup with:
        
        st.sidebar.subheader("🔑 AWS Configuration")
        
        # AWS credentials input
        use_manual_creds = st.sidebar.checkbox("Use manual credentials", value=False)
        
        aws_config = {
            'region': st.sidebar.selectbox("AWS Region", [
                'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
                'eu-west-1', 'eu-central-1', 'ap-southeast-1', 'ap-northeast-1'
            ])
        }
        
        if use_manual_creds:
            aws_config.update({
                'access_key': st.sidebar.text_input("AWS Access Key ID", type="password"),
                'secret_key': st.sidebar.text_input("AWS Secret Access Key", type="password")
            })
        
        # Initialize connector
        if 'aws_connector' not in st.session_state:
            st.session_state.aws_connector = ImprovedAWSCloudWatchConnector(aws_config)
        
        # Display connection status
        status_text, status_type = st.session_state.aws_connector.get_connection_status_display()
        
        if status_type == "success":
            st.sidebar.success(status_text)
        elif status_type == "warning":
            st.sidebar.warning(status_text)
        elif status_type == "error":
            st.sidebar.error(status_text)
        else:
            st.sidebar.info(status_text)
        
        # Connection test button
        if st.sidebar.button("🔌 Test AWS Connection"):
            success, message = st.session_state.aws_connector.test_connection()
            if success:
                st.sidebar.success(f"✅ {message}")
            else:
                st.sidebar.error(f"❌ {message}")
        
        # Diagnosis button
        if st.sidebar.button("🔍 Diagnose Connection Issues"):
            st.session_state.show_diagnosis = True
        
        # Show diagnosis if requested
        if getattr(st.session_state, 'show_diagnosis', False):
            st.session_state.aws_connector.diagnose_connection_issues()
            st.session_state.aws_connector.show_required_iam_policy()
            
            if st.button("Close Diagnosis"):
                st.session_state.show_diagnosis = False
                st.rerun()
        
        return st.session_state.aws_connector
    
    def get_cloudwatch_metrics(self, metric_queries: List[Dict], 
                              start_time: datetime, end_time: datetime) -> Dict[str, List]:
        """Get CloudWatch metrics"""
        if self.demo_mode:
            return self._generate_demo_cloudwatch_data(metric_queries)
        
        try:
            results = {}
            
            for query in metric_queries:
                response = self.cloudwatch.get_metric_statistics(
                    Namespace=query['namespace'],
                    MetricName=query['metric_name'],
                    Dimensions=query.get('dimensions', []),
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=query.get('period', 300),
                    Statistics=query.get('statistics', ['Average'])
                )
                
                results[query['key']] = response['Datapoints']
            
            return results
            
        except Exception as e:
            st.error(f"Failed to retrieve CloudWatch metrics: {str(e)}")
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
            response = self.rds.describe_db_instances()
            sql_instances = []
            
            for db in response['DBInstances']:
                if 'sqlserver' in db['Engine'].lower():
                    sql_instances.append(db)
            
            return sql_instances
            
        except Exception as e:
            st.error(f"Failed to retrieve RDS instances: {str(e)}")
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
            response = self.ec2.describe_instances(
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
            st.error(f"Failed to retrieve EC2 instances: {str(e)}")
            return []
    
    def get_cloudwatch_logs(self, log_group: str, hours: int = 24) -> List[Dict]:
        """Get CloudWatch logs"""
        if self.demo_mode:
            return self._generate_demo_log_data()
        
        try:
            start_time = int((datetime.now() - timedelta(hours=hours)).timestamp() * 1000)
            end_time = int(datetime.now().timestamp() * 1000)
            
            response = self.logs.filter_log_events(
                logGroupName=log_group,
                startTime=start_time,
                endTime=end_time
            )
            
            return response['events']
            
        except Exception as e:
            st.error(f"Failed to retrieve CloudWatch logs: {str(e)}")
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
            response = self.logs.describe_log_groups()
            return [lg['logGroupName'] for lg in response['logGroups']]
        except Exception as e:
            st.error(f"Failed to retrieve log groups: {str(e)}")
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
            
            for log_group in log_groups:
                try:
                    if filter_pattern:
                        response = self.logs.filter_log_events(
                            logGroupName=log_group,
                            startTime=start_time,
                            endTime=end_time,
                            filterPattern=filter_pattern
                        )
                    else:
                        response = self.logs.filter_log_events(
                            logGroupName=log_group,
                            startTime=start_time,
                            endTime=end_time
                        )
                    
                    all_logs[log_group] = response['events']
                    
                except Exception as e:
                    st.warning(f"Could not retrieve logs from {log_group}: {str(e)}")
                    all_logs[log_group] = []
            
            return all_logs
            
        except Exception as e:
            st.error(f"Failed to retrieve SQL Server logs: {str(e)}")
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
            # Get account ID
            sts = self.session.client('sts')
            identity = sts.get_caller_identity()
            account_id = identity['Account']
            
            # Get account alias (if available)
            iam = self.session.client('iam')
            try:
                aliases = iam.list_account_aliases()
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
            st.error(f"Failed to get account information: {str(e)}")
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
            st.error(f"Failed to get AG status from CloudWatch: {str(e)}")
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
                response = self.cloudwatch.ssm.send_command(
                    InstanceIds=[context.get('instance_id')],
                    DocumentName="AWS-ResizeInstance",
                    Parameters={
                        'InstanceType': [self._get_next_instance_size(context.get('current_instance_type'))]
                    }
                )
                return {'status': 'success', 'message': 'Instance scaling initiated'}
            
            # For RDS instances
            elif context.get('instance_type') == 'rds':
                self.cloudwatch.rds.modify_db_instance(
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
            
            response = self.cloudwatch.ssm.send_command(
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
            
            response = self.cloudwatch.ssm.send_command(
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
            
            response = self.cloudwatch.ssm.send_command(
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
            
            response = self.cloudwatch.ssm.send_command(
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
            
            response = self.cloudwatch.ssm.send_command(
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
            # self.cloudwatch.session.client('sns').publish(
            #     TopicArn='arn:aws:sns:region:account:dba-alerts',
            #     Message=message,
            #     Subject='SQL Server Auto-Remediation Alert'
            # )
            
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
    st.markdown('<div class="aws-header"><h1>☁️ AWS CloudWatch SQL Server Monitor</h1><p>Enterprise-grade monitoring with AI-powered analytics and auto-remediation</p></div>', unsafe_allow_html=True)
    
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
        
        # System Status
        st.subheader("📊 System Status")
        if not AWS_AVAILABLE:
            st.error("❌ boto3 not available")
            st.info("💡 Install boto3 for AWS connectivity")
        else:
            st.success("✅ boto3 available")
        
        if not ANTHROPIC_AVAILABLE:
            st.warning("⚠️ anthropic not available")
            st.info("💡 Install anthropic for AI features")
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
        
        # SQL Server Configuration
        st.subheader("🗄️ SQL Server Configuration")
        
        with st.expander("📋 SQL Server Metrics Setup Guide", expanded=False):
            st.markdown("""
            ### 🔧 Setting Up Comprehensive SQL Server Metrics in CloudWatch
            
            To get all the detailed SQL Server metrics shown in this dashboard, you need to set up custom metric collection:
            
            #### 1. Install CloudWatch Agent on EC2 Instances
            ```bash
            # Download and install CloudWatch agent
            wget https://s3.amazonaws.com/amazoncloudwatch-agent/windows/amd64/latest/amazon-cloudwatch-agent.msi
            msiexec /i amazon-cloudwatch-agent.msi /quiet
            ```
            
            #### 2. Configure Performance Counters
            Create a PowerShell script to collect SQL Server performance counters:
            
            ```powershell
            # SQL Server Performance Counter Collection Script
            $counters = @(
                "\\SQLServer:Buffer Manager\\Buffer cache hit ratio",
                "\\SQLServer:Buffer Manager\\Page life expectancy",
                "\\SQLServer:SQL Statistics\\Batch Requests/sec",
                "\\SQLServer:SQL Statistics\\SQL Compilations/sec",
                "\\SQLServer:SQL Statistics\\SQL Re-Compilations/sec",
                "\\SQLServer:General Statistics\\User Connections",
                "\\SQLServer:General Statistics\\Processes blocked",
                "\\SQLServer:Locks(_Total)\\Lock Waits/sec",
                "\\SQLServer:Locks(_Total)\\Lock Timeouts/sec",
                "\\SQLServer:Locks(_Total)\\Number of Deadlocks/sec",
                "\\SQLServer:Access Methods\\Full Scans/sec",
                "\\SQLServer:Access Methods\\Index Searches/sec",
                "\\SQLServer:Access Methods\\Page Splits/sec",
                "\\SQLServer:Memory Manager\\Memory Grants Pending",
                "\\SQLServer:Memory Manager\\Target Server Memory (KB)",
                "\\SQLServer:Memory Manager\\Total Server Memory (KB)"
            )
            
            foreach ($counter in $counters) {
                $value = (Get-Counter $counter).CounterSamples.CookedValue
                aws cloudwatch put-metric-data --namespace "CWAgent" --metric-data MetricName="$counter",Value=$value
            }
            ```
            
            #### 3. Always On Availability Groups Metrics
            Use this T-SQL script to collect AG metrics:
            
            ```sql
            -- Always On AG Metrics Collection
            DECLARE @MetricData TABLE (
                MetricName NVARCHAR(255),
                MetricValue FLOAT,
                Unit NVARCHAR(50)
            )
            
            -- Log Send Queue Size
            INSERT INTO @MetricData
            SELECT 
                'SQLServer:Database Replica\\Log Send Queue Size',
                log_send_queue_size,
                'Kilobytes'
            FROM sys.dm_hadr_database_replica_states
            WHERE is_local = 1
            
            -- Redo Queue Size  
            INSERT INTO @MetricData
            SELECT 
                'SQLServer:Database Replica\\Redo Queue Size',
                redo_queue_size,
                'Kilobytes'
            FROM sys.dm_hadr_database_replica_states
            WHERE is_local = 1
            
            -- Send the metrics to CloudWatch
            -- (Implementation would use PowerShell or custom application)
            ```
            
            #### 4. Custom Application Metrics
            For advanced metrics like query execution times and index fragmentation:
            
            ```sql
            -- Expensive Queries Detection
            SELECT 
                COUNT(*) as expensive_query_count
            FROM sys.dm_exec_query_stats qs
            CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) st
            WHERE qs.total_elapsed_time / qs.execution_count > 10000000 -- 10 seconds
            
            -- Index Fragmentation Check
            SELECT 
                AVG(avg_fragmentation_in_percent) as avg_fragmentation
            FROM sys.dm_db_index_physical_stats(DB_ID(), NULL, NULL, NULL, 'SAMPLED')
            WHERE avg_fragmentation_in_percent > 30
            ```
            
            #### 5. Schedule Metric Collection
            Use Windows Task Scheduler or AWS Systems Manager to run collection scripts every 5 minutes:
            
            ```json
            {
              "schemaVersion": "2.2",
              "description": "Collect SQL Server Metrics",
              "parameters": {},
              "mainSteps": [
                {
                  "action": "aws:runPowerShellScript",
                  "name": "collectSQLMetrics",
                  "inputs": {
                    "runCommand": [
                      "C:\\Scripts\\CollectSQLServerMetrics.ps1"
                    ]
                  }
                }
              ]
            }
            ```
            
            #### 6. Required IAM Permissions
            Your EC2 instances need these CloudWatch permissions:
            
            ```json
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "cloudwatch:PutMetricData",
                            "cloudwatch:GetMetricStatistics",
                            "cloudwatch:ListMetrics"
                        ],
                        "Resource": "*"
                    }
                ]
            }
            ```
            
            #### 7. Verify Metrics in CloudWatch
            Once configured, verify metrics appear in the AWS CloudWatch console under:
            - **Namespace**: `CWAgent`
            - **Metrics**: All the SQL Server performance counters
            
            #### 8. Dashboard Integration
            This monitoring tool will automatically detect and display all configured metrics.
            """)
        
        st.markdown("---")
        
        # AWS Configuration
        st.subheader("🔑 AWS Credentials")
        aws_access_key = st.text_input("AWS Access Key ID", type="password")
        aws_secret_key = st.text_input("AWS Secret Access Key", type="password")
        aws_region = st.selectbox("AWS Region", [
            'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
            'eu-west-1', 'eu-central-1', 'ap-southeast-1', 'ap-northeast-1'
        ])
        
        # AWS Account Information
        st.subheader("🏢 AWS Account Details")
        aws_account_id = st.text_input("AWS Account ID", 
                                    help="Your 12-digit AWS Account ID")
        aws_account_name = st.text_input("Account Name/Environment", 
                                        value="Production", 
                                        help="Environment name (e.g., Production, Staging)")

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

        # Update the aws_config dictionary if credentials are provided
        if aws_access_key and aws_secret_key:
            aws_config.update({
                'access_key': aws_access_key,
                'secret_key': aws_secret_key,
                'region': aws_region,
                'account_id': aws_account_id,
                'account_name': aws_account_name,
                'log_groups': [lg.strip() for lg in log_groups if lg.strip()],
                'custom_namespace': custom_namespace,
                'os_metrics_namespace': os_metrics_namespace,
                'enable_os_metrics': enable_os_metrics
            })
            
            if st.session_state.cloudwatch_connector is None:
                st.session_state.cloudwatch_connector = AWSCloudWatchConnector(aws_config)
                st.session_state.always_on_monitor = AlwaysOnMonitor(st.session_state.cloudwatch_connector)
                st.session_state.auto_remediation = AutoRemediationEngine(st.session_state.cloudwatch_connector)
                st.session_state.predictive_analytics = PredictiveAnalyticsEngine(st.session_state.cloudwatch_connector)
            
            if st.button("🔌 Test AWS Connection"):
                if st.session_state.cloudwatch_connector.test_connection():
                    st.success("✅ AWS Connected")
                else:
                    st.error("❌ AWS Connection Failed")
        
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
        st.session_state.cloudwatch_connector = AWSCloudWatchConnector(aws_config)
        st.session_state.always_on_monitor = AlwaysOnMonitor(st.session_state.cloudwatch_connector)
        st.session_state.auto_remediation = AutoRemediationEngine(st.session_state.cloudwatch_connector)
        st.session_state.predictive_analytics = PredictiveAnalyticsEngine(st.session_state.cloudwatch_connector)

    # =================== Enhanced Data Collection ===================
    def collect_comprehensive_metrics():
        """Collect all metrics including OS, SQL Server, and logs"""
        current_time = datetime.now()
        start_time = current_time - timedelta(hours=24)
        
        all_metrics = {}
        all_logs = {}
        
        # Get AWS account information
        if st.session_state.cloudwatch_connector:
            account_info = st.session_state.cloudwatch_connector.get_account_info()
            
            # Display account info in sidebar
            if account_info:
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
        
        return all_metrics, all_logs, ec2_instances

    # Collect metrics
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
            
            # Create metric categories
            metric_categories = st.tabs([
                "🏃 Performance", 
                "🧠 Memory", 
                "🔒 Locking", 
                "📊 Wait Stats",
                "🔄 Always On",
                "💾 Database",
                "🛡️ Security"
            ])
            
            # ===== PERFORMANCE METRICS =====
            with metric_categories[0]:
                st.subheader("🏃 SQL Server Performance Metrics")
                
                col1, col2, col3, col4 = st.columns(4)
                
                # Get metrics for selected instance
                buffer_cache_data = all_metrics.get(f"{selected_instance}_buffer_cache_hit_ratio", [])
                batch_requests_data = all_metrics.get(f"{selected_instance}_batch_requests_per_sec", [])
                compilations_data = all_metrics.get(f"{selected_instance}_sql_compilations_per_sec", [])
                recompilations_data = all_metrics.get(f"{selected_instance}_sql_recompilations_per_sec", [])
                
                if buffer_cache_data:
                    current_buffer_cache = buffer_cache_data[-1]['Average']
                    color = "🟢" if current_buffer_cache > 95 else "🟡" if current_buffer_cache > 90 else "🔴"
                    with col1:
                        st.metric(f"Buffer Cache Hit Ratio {color}", f"{current_buffer_cache:.2f}%")
                
                if batch_requests_data:
                    current_batch_requests = batch_requests_data[-1]['Average']
                    with col2:
                        st.metric("Batch Requests/sec", f"{current_batch_requests:.0f}")
                
                if compilations_data:
                    current_compilations = compilations_data[-1]['Average']
                    color = "🔴" if current_compilations > 100 else "🟡" if current_compilations > 50 else "🟢"
                    with col3:
                        st.metric(f"SQL Compilations/sec {color}", f"{current_compilations:.0f}")
                
                if recompilations_data:
                    current_recompilations = recompilations_data[-1]['Average']
                    color = "🔴" if current_recompilations > 10 else "🟡" if current_recompilations > 5 else "🟢"
                    with col4:
                        st.metric(f"SQL Re-Compilations/sec {color}", f"{current_recompilations:.0f}")
                
                # Performance trends chart
                if buffer_cache_data and batch_requests_data:
                    fig = make_subplots(
                        rows=2, cols=2,
                        subplot_titles=('Buffer Cache Hit Ratio', 'Batch Requests/sec', 
                                       'SQL Compilations/sec', 'Page Life Expectancy'),
                        specs=[[{"secondary_y": False}, {"secondary_y": False}],
                               [{"secondary_y": False}, {"secondary_y": False}]]
                    )
                    
                    # Buffer Cache Hit Ratio
                    fig.add_trace(
                        go.Scatter(x=[dp['Timestamp'] for dp in buffer_cache_data],
                                  y=[dp['Average'] for dp in buffer_cache_data],
                                  name='Buffer Cache Hit %', line=dict(color='blue')),
                        row=1, col=1
                    )
                    
                    # Batch Requests
                    fig.add_trace(
                        go.Scatter(x=[dp['Timestamp'] for dp in batch_requests_data],
                                  y=[dp['Average'] for dp in batch_requests_data],
                                  name='Batch Requests/sec', line=dict(color='green')),
                        row=1, col=2
                    )
                    
                    # SQL Compilations
                    if compilations_data:
                        fig.add_trace(
                            go.Scatter(x=[dp['Timestamp'] for dp in compilations_data],
                                      y=[dp['Average'] for dp in compilations_data],
                                      name='Compilations/sec', line=dict(color='orange')),
                            row=2, col=1
                        )
                    
                    # Page Life Expectancy
                    page_life_data = all_metrics.get(f"{selected_instance}_page_life_expectancy", [])
                    if page_life_data:
                        fig.add_trace(
                            go.Scatter(x=[dp['Timestamp'] for dp in page_life_data],
                                      y=[dp['Average'] for dp in page_life_data],
                                      name='Page Life Exp (sec)', line=dict(color='red')),
                            row=2, col=2
                        )
                    
                    fig.update_layout(height=600, showlegend=False, title_text="SQL Server Performance Trends")
                    st.plotly_chart(fig, use_container_width=True)
            
            # ===== MEMORY METRICS =====
            with metric_categories[1]:
                st.subheader("🧠 SQL Server Memory Metrics")
                
                col1, col2, col3, col4 = st.columns(4)
                
                target_memory_data = all_metrics.get(f"{selected_instance}_target_server_memory_kb", [])
                total_memory_data = all_metrics.get(f"{selected_instance}_total_server_memory_kb", [])
                memory_grants_pending_data = all_metrics.get(f"{selected_instance}_memory_grants_pending", [])
                page_life_data = all_metrics.get(f"{selected_instance}_page_life_expectancy", [])
                
                if target_memory_data and total_memory_data:
                    target_memory_gb = target_memory_data[-1]['Average'] / 1024 / 1024
                    total_memory_gb = total_memory_data[-1]['Average'] / 1024 / 1024
                    memory_utilization = (total_memory_gb / target_memory_gb) * 100
                    
                    with col1:
                        st.metric("Target Memory", f"{target_memory_gb:.1f} GB")
                    with col2:
                        st.metric("Total Memory", f"{total_memory_gb:.1f} GB")
                    with col3:
                        color = "🔴" if memory_utilization > 95 else "🟡" if memory_utilization > 85 else "🟢"
                        st.metric(f"Memory Utilization {color}", f"{memory_utilization:.1f}%")
                
                if memory_grants_pending_data:
                    pending_grants = memory_grants_pending_data[-1]['Average']
                    color = "🔴" if pending_grants > 5 else "🟡" if pending_grants > 1 else "🟢"
                    with col4:
                        st.metric(f"Memory Grants Pending {color}", f"{pending_grants:.0f}")
                
                if page_life_data:
                    page_life_value = page_life_data[-1]['Average']
                    color = "🔴" if page_life_value < 300 else "🟡" if page_life_value < 1000 else "🟢"
                    st.metric(f"Page Life Expectancy {color}", f"{page_life_value:.0f} seconds")
                
                # Memory trend chart
                if target_memory_data and total_memory_data:
                    fig = go.Figure()
                    
                    fig.add_trace(go.Scatter(
                        x=[dp['Timestamp'] for dp in target_memory_data],
                        y=[dp['Average']/1024/1024 for dp in target_memory_data],
                        name='Target Memory (GB)',
                        line=dict(color='blue')
                    ))
                    
                    fig.add_trace(go.Scatter(
                        x=[dp['Timestamp'] for dp in total_memory_data],
                        y=[dp['Average']/1024/1024 for dp in total_memory_data],
                        name='Total Memory (GB)',
                        line=dict(color='red')
                    ))
                    
                    fig.update_layout(title="SQL Server Memory Usage Trends", 
                                    xaxis_title="Time", yaxis_title="Memory (GB)")
                    st.plotly_chart(fig, use_container_width=True)
            
            # ===== LOCKING METRICS =====
            with metric_categories[2]:
                st.subheader("🔒 SQL Server Locking and Blocking Metrics")
                
                col1, col2, col3, col4 = st.columns(4)
                
                lock_waits_data = all_metrics.get(f"{selected_instance}_lock_waits_per_sec", [])
                lock_timeouts_data = all_metrics.get(f"{selected_instance}_lock_timeouts_per_sec", [])
                deadlocks_data = all_metrics.get(f"{selected_instance}_deadlocks_per_sec", [])
                processes_blocked_data = all_metrics.get(f"{selected_instance}_processes_blocked", [])
                
                if lock_waits_data:
                    lock_waits = lock_waits_data[-1]['Average']
                    color = "🔴" if lock_waits > 50 else "🟡" if lock_waits > 20 else "🟢"
                    with col1:
                        st.metric(f"Lock Waits/sec {color}", f"{lock_waits:.1f}")
                
                if lock_timeouts_data:
                    lock_timeouts = lock_timeouts_data[-1]['Average']
                    color = "🔴" if lock_timeouts > 5 else "🟡" if lock_timeouts > 1 else "🟢"
                    with col2:
                        st.metric(f"Lock Timeouts/sec {color}", f"{lock_timeouts:.1f}")
                
                if deadlocks_data:
                    deadlocks = deadlocks_data[-1]['Average']
                    color = "🔴" if deadlocks > 0.1 else "🟡" if deadlocks > 0 else "🟢"
                    with col3:
                        st.metric(f"Deadlocks/sec {color}", f"{deadlocks:.2f}")
                
                if processes_blocked_data:
                    blocked_processes = processes_blocked_data[-1]['Average']
                    color = "🔴" if blocked_processes > 5 else "🟡" if blocked_processes > 0 else "🟢"
                    with col4:
                        st.metric(f"Processes Blocked {color}", f"{blocked_processes:.0f}")
                
                # Locking trends chart
                if lock_waits_data and deadlocks_data:
                    fig = make_subplots(
                        rows=2, cols=1,
                        subplot_titles=('Lock Waits per Second', 'Deadlocks per Second')
                    )
                    
                    fig.add_trace(
                        go.Scatter(x=[dp['Timestamp'] for dp in lock_waits_data],
                                  y=[dp['Average'] for dp in lock_waits_data],
                                  name='Lock Waits/sec', line=dict(color='orange')),
                        row=1, col=1
                    )
                    
                    fig.add_trace(
                        go.Scatter(x=[dp['Timestamp'] for dp in deadlocks_data],
                                  y=[dp['Average'] for dp in deadlocks_data],
                                  name='Deadlocks/sec', line=dict(color='red')),
                        row=2, col=1
                    )
                    
                    fig.update_layout(height=500, showlegend=False, title_text="Locking and Blocking Trends")
                    st.plotly_chart(fig, use_container_width=True)
            
            # ===== WAIT STATISTICS =====
            with metric_categories[3]:
                st.subheader("📊 SQL Server Wait Statistics")
                
                # Top wait types
                wait_types = [
                    ('CXPACKET', all_metrics.get(f"{selected_instance}_wait_cxpacket_ms", [])),
                    ('ASYNC_NETWORK_IO', all_metrics.get(f"{selected_instance}_wait_async_network_io_ms", [])),
                    ('PAGEIOLATCH_SH', all_metrics.get(f"{selected_instance}_wait_pageiolatch_sh_ms", [])),
                    ('PAGEIOLATCH_EX', all_metrics.get(f"{selected_instance}_wait_pageiolatch_ex_ms", [])),
                    ('WRITELOG', all_metrics.get(f"{selected_instance}_wait_writelog_ms", [])),
                    ('RESOURCE_SEMAPHORE', all_metrics.get(f"{selected_instance}_wait_resource_semaphore_ms", []))
                ]
                
                # Current wait times
                current_waits = []
                for wait_name, wait_data in wait_types:
                    if wait_data:
                        current_waits.append({
                            'Wait Type': wait_name,
                            'Current Wait Time (ms)': wait_data[-1]['Average'],
                            'Status': '🔴' if wait_data[-1]['Average'] > 1000 else '🟡' if wait_data[-1]['Average'] > 100 else '🟢'
                        })
                
                if current_waits:
                    waits_df = pd.DataFrame(current_waits)
                    waits_df = waits_df.sort_values('Current Wait Time (ms)', ascending=False)
                    st.dataframe(waits_df, use_container_width=True)
                    
                    # Wait statistics chart
                    fig = go.Figure()
                    
                    for wait_name, wait_data in wait_types[:4]:  # Top 4 wait types
                        if wait_data:
                            fig.add_trace(go.Scatter(
                                x=[dp['Timestamp'] for dp in wait_data],
                                y=[dp['Average'] for dp in wait_data],
                                name=wait_name,
                                mode='lines'
                            ))
                    
                    fig.update_layout(title="Top Wait Types Trends", 
                                    xaxis_title="Time", yaxis_title="Wait Time (ms)")
                    st.plotly_chart(fig, use_container_width=True)
            
            # ===== ALWAYS ON METRICS =====
            with metric_categories[4]:
                st.subheader("🔄 Always On Availability Groups Metrics")
                
                col1, col2, col3, col4 = st.columns(4)
                
                log_send_queue_data = all_metrics.get(f"{selected_instance}_ag_log_send_queue_size", [])
                log_send_rate_data = all_metrics.get(f"{selected_instance}_ag_log_send_rate", [])
                redo_queue_data = all_metrics.get(f"{selected_instance}_ag_redo_queue_size", [])
                redo_rate_data = all_metrics.get(f"{selected_instance}_ag_redo_rate", [])
                
                if log_send_queue_data:
                    log_send_queue_mb = log_send_queue_data[-1]['Average'] / 1024
                    color = "🔴" if log_send_queue_mb > 100 else "🟡" if log_send_queue_mb > 50 else "🟢"
                    with col1:
                        st.metric(f"Log Send Queue {color}", f"{log_send_queue_mb:.1f} MB")
                
                if log_send_rate_data:
                    log_send_rate_mb = log_send_rate_data[-1]['Average'] / 1024
                    with col2:
                        st.metric("Log Send Rate", f"{log_send_rate_mb:.1f} MB/s")
                
                if redo_queue_data:
                    redo_queue_mb = redo_queue_data[-1]['Average'] / 1024
                    color = "🔴" if redo_queue_mb > 50 else "🟡" if redo_queue_mb > 25 else "🟢"
                    with col3:
                        st.metric(f"Redo Queue {color}", f"{redo_queue_mb:.1f} MB")
                
                if redo_rate_data:
                    redo_rate_mb = redo_rate_data[-1]['Average'] / 1024
                    with col4:
                        st.metric("Redo Rate", f"{redo_rate_mb:.1f} MB/s")
                
                # Always On trends
                if log_send_queue_data and redo_queue_data:
                    fig = make_subplots(
                        rows=2, cols=1,
                        subplot_titles=('Log Send Queue Size (MB)', 'Redo Queue Size (MB)')
                    )
                    
                    fig.add_trace(
                        go.Scatter(x=[dp['Timestamp'] for dp in log_send_queue_data],
                                  y=[dp['Average']/1024 for dp in log_send_queue_data],
                                  name='Log Send Queue (MB)', line=dict(color='blue')),
                        row=1, col=1
                    )
                    
                    fig.add_trace(
                        go.Scatter(x=[dp['Timestamp'] for dp in redo_queue_data],
                                  y=[dp['Average']/1024 for dp in redo_queue_data],
                                  name='Redo Queue (MB)', line=dict(color='red')),
                        row=2, col=1
                    )
                    
                    fig.update_layout(height=500, showlegend=False, title_text="Always On AG Performance")
                    st.plotly_chart(fig, use_container_width=True)
            
            # ===== DATABASE METRICS =====
            with metric_categories[5]:
                st.subheader("💾 Database-Level Metrics")
                
                col1, col2, col3, col4 = st.columns(4)
                
                data_file_size_data = all_metrics.get(f"{selected_instance}_db_data_file_size_kb", [])
                log_file_size_data = all_metrics.get(f"{selected_instance}_db_log_file_size_kb", [])
                log_used_percent_data = all_metrics.get(f"{selected_instance}_db_percent_log_used", [])
                transactions_data = all_metrics.get(f"{selected_instance}_db_transactions_per_sec", [])
                
                if data_file_size_data:
                    data_size_gb = data_file_size_data[-1]['Average'] / 1024 / 1024
                    with col1:
                        st.metric("Data File Size", f"{data_size_gb:.1f} GB")
                
                if log_file_size_data:
                    log_size_gb = log_file_size_data[-1]['Average'] / 1024 / 1024
                    with col2:
                        st.metric("Log File Size", f"{log_size_gb:.1f} GB")
                
                if log_used_percent_data:
                    log_used_percent = log_used_percent_data[-1]['Average']
                    color = "🔴" if log_used_percent > 80 else "🟡" if log_used_percent > 60 else "🟢"
                    with col3:
                        st.metric(f"Log Used % {color}", f"{log_used_percent:.1f}%")
                
                if transactions_data:
                    transactions_per_sec = transactions_data[-1]['Average']
                    with col4:
                        st.metric("Transactions/sec", f"{transactions_per_sec:.0f}")
                
                # Database growth trends
                if data_file_size_data and log_file_size_data:
                    fig = go.Figure()
                    
                    fig.add_trace(go.Scatter(
                        x=[dp['Timestamp'] for dp in data_file_size_data],
                        y=[dp['Average']/1024/1024 for dp in data_file_size_data],
                        name='Data File Size (GB)',
                        line=dict(color='blue')
                    ))
                    
                    fig.add_trace(go.Scatter(
                        x=[dp['Timestamp'] for dp in log_file_size_data],
                        y=[dp['Average']/1024/1024 for dp in log_file_size_data],
                        name='Log File Size (GB)',
                        line=dict(color='red')
                    ))
                    
                    fig.update_layout(title="Database File Size Trends", 
                                    xaxis_title="Time", yaxis_title="Size (GB)")
                    st.plotly_chart(fig, use_container_width=True)
            
            # ===== SECURITY METRICS =====
            with metric_categories[6]:
                st.subheader("🛡️ SQL Server Security Metrics")
                
                col1, col2, col3, col4 = st.columns(4)
                
                failed_logins_data = all_metrics.get(f"{selected_instance}_failed_logins_per_sec", [])
                user_connections_data = all_metrics.get(f"{selected_instance}_user_connections", [])
                logins_data = all_metrics.get(f"{selected_instance}_logins_per_sec", [])
                logouts_data = all_metrics.get(f"{selected_instance}_logouts_per_sec", [])
                
                if failed_logins_data:
                    failed_logins = failed_logins_data[-1]['Average']
                    color = "🔴" if failed_logins > 5 else "🟡" if failed_logins > 1 else "🟢"
                    with col1:
                        st.metric(f"Failed Logins/sec {color}", f"{failed_logins:.1f}")
                
                if user_connections_data:
                    user_connections = user_connections_data[-1]['Average']
                    color = "🔴" if user_connections > 200 else "🟡" if user_connections > 100 else "🟢"
                    with col2:
                        st.metric(f"User Connections {color}", f"{user_connections:.0f}")
                
                if logins_data:
                    logins_per_sec = logins_data[-1]['Average']
                    with col3:
                        st.metric("Logins/sec", f"{logins_per_sec:.1f}")
                
                if logouts_data:
                    logouts_per_sec = logouts_data[-1]['Average']
                    with col4:
                        st.metric("Logouts/sec", f"{logouts_per_sec:.1f}")
                
                # Security trends
                if failed_logins_data and user_connections_data:
                    fig = make_subplots(
                        rows=2, cols=1,
                        subplot_titles=('Failed Logins per Second', 'User Connections')
                    )
                    
                    fig.add_trace(
                        go.Scatter(x=[dp['Timestamp'] for dp in failed_logins_data],
                                  y=[dp['Average'] for dp in failed_logins_data],
                                  name='Failed Logins/sec', line=dict(color='red')),
                        row=1, col=1
                    )
                    
                    fig.add_trace(
                        go.Scatter(x=[dp['Timestamp'] for dp in user_connections_data],
                                  y=[dp['Average'] for dp in user_connections_data],
                                  name='User Connections', line=dict(color='blue')),
                        row=2, col=1
                    )
                    
                    fig.update_layout(height=500, showlegend=False, title_text="Security Metrics Trends")
                    st.plotly_chart(fig, use_container_width=True)
        
        else:
            st.warning("No EC2 SQL Server instances found. Please ensure instances are properly tagged.")
    
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
            
            # OS Metric Categories
            os_categories = st.tabs([
                "💻 CPU & Load", 
                "🧠 Memory", 
                "💾 Disk I/O", 
                "🌐 Network",
                "⚙️ Processes",
                "📊 System Health"
            ])
            
            # ===== CPU & LOAD METRICS =====
            with os_categories[0]:
                st.subheader("💻 CPU Utilization & System Load")
                
                col1, col2, col3, col4 = st.columns(4)
                
                # Get CPU metrics for selected instance
                cpu_active_data = all_metrics.get(f"{selected_instance}_os_cpu_usage_active", [])
                cpu_system_data = all_metrics.get(f"{selected_instance}_os_cpu_usage_system", [])
                cpu_user_data = all_metrics.get(f"{selected_instance}_os_cpu_usage_user", [])
                cpu_iowait_data = all_metrics.get(f"{selected_instance}_os_cpu_usage_iowait", [])
                
                if cpu_active_data:
                    current_cpu = cpu_active_data[-1]['Average']
                    color = "🔴" if current_cpu > 80 else "🟡" if current_cpu > 60 else "🟢"
                    with col1:
                        st.metric(f"CPU Active {color}", f"{current_cpu:.1f}%")
                
                if cpu_system_data:
                    current_system = cpu_system_data[-1]['Average']
                    with col2:
                        st.metric("System CPU", f"{current_system:.1f}%")
                
                if cpu_user_data:
                    current_user = cpu_user_data[-1]['Average']
                    with col3:
                        st.metric("User CPU", f"{current_user:.1f}%")
                
                if cpu_iowait_data:
                    current_iowait = cpu_iowait_data[-1]['Average']
                    color = "🔴" if current_iowait > 20 else "🟡" if current_iowait > 10 else "🟢"
                    with col4:
                        st.metric(f"I/O Wait {color}", f"{current_iowait:.1f}%")
                
                # CPU breakdown chart
                if cpu_active_data and cpu_system_data and cpu_user_data:
                    fig = go.Figure()
                    
                    fig.add_trace(go.Scatter(
                        x=[dp['Timestamp'] for dp in cpu_active_data],
                        y=[dp['Average'] for dp in cpu_active_data],
                        name='Total CPU Active',
                        line=dict(color='red')
                    ))
                    
                    fig.add_trace(go.Scatter(
                        x=[dp['Timestamp'] for dp in cpu_system_data],
                        y=[dp['Average'] for dp in cpu_system_data],
                        name='System CPU',
                        line=dict(color='orange')
                    ))
                    
                    fig.add_trace(go.Scatter(
                        x=[dp['Timestamp'] for dp in cpu_user_data],
                        y=[dp['Average'] for dp in cpu_user_data],
                        name='User CPU',
                        line=dict(color='blue')
                    ))
                    
                    fig.update_layout(title="CPU Utilization Breakdown", 
                                    xaxis_title="Time", yaxis_title="CPU %")
                    st.plotly_chart(fig, use_container_width=True)
            
            # ===== MEMORY METRICS =====
            with os_categories[1]:
                st.subheader("🧠 Memory Utilization")
                
                col1, col2, col3, col4 = st.columns(4)
                
                mem_used_percent_data = all_metrics.get(f"{selected_instance}_os_mem_used_percent", [])
                mem_available_data = all_metrics.get(f"{selected_instance}_os_mem_available_percent", [])
                mem_cached_data = all_metrics.get(f"{selected_instance}_os_mem_cached", [])
                
                if mem_used_percent_data:
                    current_mem = mem_used_percent_data[-1]['Average']
                    color = "🔴" if current_mem > 90 else "🟡" if current_mem > 80 else "🟢"
                    with col1:
                        st.metric(f"Memory Used {color}", f"{current_mem:.1f}%")
                
                if mem_available_data:
                    available_mem = mem_available_data[-1]['Average']
                    with col2:
                        st.metric("Memory Available", f"{available_mem:.1f}%")
                
                if mem_cached_data:
                    cached_mem = mem_cached_data[-1]['Average'] / 1024 / 1024  # Convert to MB
                    with col3:
                        st.metric("Cached Memory", f"{cached_mem:.1f} MB")
                
                # Memory usage chart
                if mem_used_percent_data and mem_available_data:
                    fig = go.Figure()
                    
                    fig.add_trace(go.Scatter(
                        x=[dp['Timestamp'] for dp in mem_used_percent_data],
                        y=[dp['Average'] for dp in mem_used_percent_data],
                        name='Memory Used %',
                        line=dict(color='red')
                    ))
                    
                    fig.add_trace(go.Scatter(
                        x=[dp['Timestamp'] for dp in mem_available_data],
                        y=[dp['Average'] for dp in mem_available_data],
                        name='Memory Available %',
                        line=dict(color='green')
                    ))
                    
                    fig.update_layout(title="Memory Utilization Trends", 
                                    xaxis_title="Time", yaxis_title="Memory %")
                    st.plotly_chart(fig, use_container_width=True)
            
            # ===== DISK I/O METRICS =====
            with os_categories[2]:
                st.subheader("💾 Disk I/O Performance")
                
                col1, col2, col3, col4 = st.columns(4)
                
                disk_used_data = all_metrics.get(f"{selected_instance}_os_disk_used_percent", [])
                disk_read_bytes_data = all_metrics.get(f"{selected_instance}_os_diskio_read_bytes", [])
                disk_write_bytes_data = all_metrics.get(f"{selected_instance}_os_diskio_write_bytes", [])
                disk_io_time_data = all_metrics.get(f"{selected_instance}_os_diskio_io_time", [])
                
                if disk_used_data:
                    disk_used = disk_used_data[-1]['Average']
                    color = "🔴" if disk_used > 90 else "🟡" if disk_used > 80 else "🟢"
                    with col1:
                        st.metric(f"Disk Used {color}", f"{disk_used:.1f}%")
                
                if disk_read_bytes_data:
                    read_mb = disk_read_bytes_data[-1]['Average'] / 1024 / 1024
                    with col2:
                        st.metric("Disk Read", f"{read_mb:.1f} MB/s")
                
                if disk_write_bytes_data:
                    write_mb = disk_write_bytes_data[-1]['Average'] / 1024 / 1024
                    with col3:
                        st.metric("Disk Write", f"{write_mb:.1f} MB/s")
                
                if disk_io_time_data:
                    io_time = disk_io_time_data[-1]['Average']
                    color = "🔴" if io_time > 50 else "🟡" if io_time > 25 else "🟢"
                    with col4:
                        st.metric(f"I/O Time {color}", f"{io_time:.1f}%")
                
                # Disk I/O chart
                if disk_read_bytes_data and disk_write_bytes_data:
                    fig = go.Figure()
                    
                    fig.add_trace(go.Scatter(
                        x=[dp['Timestamp'] for dp in disk_read_bytes_data],
                        y=[dp['Average']/1024/1024 for dp in disk_read_bytes_data],
                        name='Disk Read (MB/s)',
                        line=dict(color='blue')
                    ))
                    
                    fig.add_trace(go.Scatter(
                        x=[dp['Timestamp'] for dp in disk_write_bytes_data],
                        y=[dp['Average']/1024/1024 for dp in disk_write_bytes_data],
                        name='Disk Write (MB/s)',
                        line=dict(color='red')
                    ))
                    
                    fig.update_layout(title="Disk I/O Performance", 
                                    xaxis_title="Time", yaxis_title="MB/s")
                    st.plotly_chart(fig, use_container_width=True)
            
            # ===== NETWORK METRICS =====
            with os_categories[3]:
                st.subheader("🌐 Network Performance")
                
                col1, col2, col3, col4 = st.columns(4)
                
                net_bytes_sent_data = all_metrics.get(f"{selected_instance}_os_net_bytes_sent", [])
                net_bytes_recv_data = all_metrics.get(f"{selected_instance}_os_net_bytes_recv", [])
                net_packets_sent_data = all_metrics.get(f"{selected_instance}_os_net_packets_sent", [])
                net_packets_recv_data = all_metrics.get(f"{selected_instance}_os_net_packets_recv", [])
                
                if net_bytes_sent_data:
                    sent_mb = net_bytes_sent_data[-1]['Average'] / 1024 / 1024
                    with col1:
                        st.metric("Network Out", f"{sent_mb:.1f} MB/s")
                
                if net_bytes_recv_data:
                    recv_mb = net_bytes_recv_data[-1]['Average'] / 1024 / 1024
                    with col2:
                        st.metric("Network In", f"{recv_mb:.1f} MB/s")
                
                if net_packets_sent_data:
                    packets_sent = net_packets_sent_data[-1]['Average']
                    with col3:
                        st.metric("Packets Out/s", f"{packets_sent:.0f}")
                
                if net_packets_recv_data:
                    packets_recv = net_packets_recv_data[-1]['Average']
                    with col4:
                        st.metric("Packets In/s", f"{packets_recv:.0f}")
                
                # Network chart
                if net_bytes_sent_data and net_bytes_recv_data:
                    fig = go.Figure()
                    
                    fig.add_trace(go.Scatter(
                        x=[dp['Timestamp'] for dp in net_bytes_sent_data],
                        y=[dp['Average']/1024/1024 for dp in net_bytes_sent_data],
                        name='Network Out (MB/s)',
                        line=dict(color='blue')
                    ))
                    
                    fig.add_trace(go.Scatter(
                        x=[dp['Timestamp'] for dp in net_bytes_recv_data],
                        y=[dp['Average']/1024/1024 for dp in net_bytes_recv_data],
                        name='Network In (MB/s)',
                        line=dict(color='green')
                    ))
                    
                    fig.update_layout(title="Network Performance", 
                                    xaxis_title="Time", yaxis_title="MB/s")
                    st.plotly_chart(fig, use_container_width=True)
            
            # ===== PROCESS METRICS =====
            with os_categories[4]:
                st.subheader("⚙️ Process Information")
                
                col1, col2, col3, col4 = st.columns(4)
                
                processes_running_data = all_metrics.get(f"{selected_instance}_os_processes_running", [])
                processes_sleeping_data = all_metrics.get(f"{selected_instance}_os_processes_sleeping", [])
                processes_blocked_data = all_metrics.get(f"{selected_instance}_os_processes_blocked", [])
                system_load1_data = all_metrics.get(f"{selected_instance}_os_system_load1", [])
                
                if processes_running_data:
                    running_procs = processes_running_data[-1]['Average']
                    with col1:
                        st.metric("Running Processes", f"{running_procs:.0f}")
                
                if processes_sleeping_data:
                    sleeping_procs = processes_sleeping_data[-1]['Average']
                    with col2:
                        st.metric("Sleeping Processes", f"{sleeping_procs:.0f}")
                
                if processes_blocked_data:
                    blocked_procs = processes_blocked_data[-1]['Average']
                    color = "🔴" if blocked_procs > 5 else "🟡" if blocked_procs > 0 else "🟢"
                    with col3:
                        st.metric(f"Blocked Processes {color}", f"{blocked_procs:.0f}")
                
                if system_load1_data:
                    load_avg = system_load1_data[-1]['Average']
                    color = "🔴" if load_avg > 4 else "🟡" if load_avg > 2 else "🟢"
                    with col4:
                        st.metric(f"Load Average {color}", f"{load_avg:.2f}")
            
            # ===== SYSTEM HEALTH =====
            with os_categories[5]:
                st.subheader("📊 Overall System Health")
                
                # System health score calculation
                health_score = 100
                health_issues = []
                
                # Check CPU
                if cpu_active_data:
                    cpu = cpu_active_data[-1]['Average']
                    if cpu > 90:
                        health_score -= 30
                        health_issues.append("Critical CPU usage")
                    elif cpu > 80:
                        health_score -= 15
                        health_issues.append("High CPU usage")
                
                # Check Memory
                if mem_used_percent_data:
                    mem = mem_used_percent_data[-1]['Average']
                    if mem > 95:
                        health_score -= 25
                        health_issues.append("Critical memory usage")
                    elif mem > 85:
                        health_score -= 10
                        health_issues.append("High memory usage")
                
                # Check Disk
                if disk_used_data:
                    disk = disk_used_data[-1]['Average']
                    if disk > 95:
                        health_score -= 20
                        health_issues.append("Critical disk usage")
                    elif disk > 85:
                        health_score -= 10
                        health_issues.append("High disk usage")
                
                # Display health score
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    health_color = "🟢" if health_score > 80 else "🟡" if health_score > 60 else "🔴"
                    st.metric(f"System Health {health_color}", f"{health_score}/100")
                
                with col2:
                    st.metric("Health Issues", len(health_issues))
                
                with col3:
                    uptime_hours = np.random.randint(24, 720)  # Demo uptime
                    st.metric("Uptime", f"{uptime_hours} hours")
                
                # Health issues list
                if health_issues:
                    st.subheader("⚠️ Health Issues")
                    for issue in health_issues:
                        st.warning(f"• {issue}")
                else:
                    st.success("✅ No health issues detected")
        
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
            
            # Remediation History
            st.subheader("📋 Recent Remediation History")
            
            if st.session_state.auto_remediation.remediation_history:
                history_data = []
                for entry in st.session_state.auto_remediation.remediation_history[-10:]:  # Last 10
                    history_data.append({
                        'Timestamp': entry['executed_at'].strftime('%Y-%m-%d %H:%M:%S'),
                        'Rule': entry['action']['rule_name'].replace('_', ' ').title(),
                        'Actions': ', '.join(entry['action']['actions']),
                        'Status': entry['status'],
                        'Results': len(entry['results'])
                    })
                
                if history_data:
                    history_df = pd.DataFrame(history_data)
                    st.dataframe(history_df, use_container_width=True)
            else:
                st.info("No remediation actions have been executed yet.")
            
            # Remediation Configuration
            st.subheader("⚙️ Remediation Configuration")
            
            with st.expander("🔧 Configure Remediation Rules"):
                st.write("**Current Remediation Rules:**")
                
                for rule_name, rule_config in st.session_state.auto_remediation.remediation_rules.items():
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        st.write(f"**{rule_name.replace('_', ' ').title()}**")
                        st.write(f"Threshold: {rule_config['threshold']}")
                    
                    with col2:
                        st.write(f"Duration: {rule_config['duration_minutes']} min")
                        st.write(f"Auto-execute: {rule_config['auto_execute']}")
                    
                    with col3:
                        st.write(f"Actions: {len(rule_config['actions'])}")
                        for action in rule_config['actions']:
                            st.write(f"  • {action}")
        
        else:
            st.warning("🔒 Auto-remediation is currently disabled")
            st.info("Enable auto-remediation in the sidebar to see available actions and configure automated responses to system issues.")
    
    # =================== Predictive Analytics Tab ===================
    with tab6:
        st.header("🔮 Predictive Analytics & Forecasting")
        
        if enable_predictive_alerts:
            # Analyze trends
            trend_analysis = st.session_state.predictive_analytics.analyze_trends(all_metrics, days=30)
            
            if trend_analysis:
                st.subheader("📊 Performance Trend Analysis")
                
                for metric_name, analysis in trend_analysis.items():
                    if analysis.get('status') == 'analyzed':
                        
                        # Create prediction visualization
                        col1, col2 = st.columns([2, 1])
                        
                        with col1:
                            # Historical vs Predicted chart
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
                            for rec in analysis['recommendations']:
                                st.write(f"• {rec}")
                        
                        st.markdown("---")
            
            # Capacity Planning
            st.subheader("📈 Capacity Planning Insights")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.write("**🔮 30-Day Forecast:**")
                
                # Simulate capacity predictions
                capacity_predictions = {
                    'CPU Usage': {'current': 65, 'predicted': 75, 'trend': 'increasing'},
                    'Memory Usage': {'current': 78, 'predicted': 82, 'trend': 'stable'},
                    'Disk Usage': {'current': 45, 'predicted': 52, 'trend': 'increasing'},
                    'Connection Count': {'current': 85, 'predicted': 92, 'trend': 'increasing'}
                }
                
                for resource, data in capacity_predictions.items():
                    trend_icon = {'increasing': '📈', 'decreasing': '📉', 'stable': '➡️'}[data['trend']]
                    color = '🔴' if data['predicted'] > 90 else '🟡' if data['predicted'] > 80 else '🟢'
                    
                    st.write(f"{color} **{resource}:** {data['current']}% → {data['predicted']}% {trend_icon}")
            
            with col2:
                st.write("**⚠️ Capacity Recommendations:**")
                st.write("• Monitor CPU usage closely - trending upward")
                st.write("• Consider scaling memory in Q2")
                st.write("• Plan disk expansion within 60 days")
                st.write("• Review connection pooling configuration")
            
            # Failure Prediction
            st.subheader("🚨 Failure Risk Assessment")
            
            failure_risks = [
                {'Component': 'Primary SQL Server', 'Risk': 'Low', 'Probability': '5%', 'Impact': 'High'},
                {'Component': 'Always On AG-Production', 'Risk': 'Medium', 'Probability': '15%', 'Impact': 'Critical'},
                {'Component': 'Backup System', 'Risk': 'Low', 'Probability': '8%', 'Impact': 'Medium'},
                {'Component': 'Storage Subsystem', 'Risk': 'Medium', 'Probability': '12%', 'Impact': 'High'}
            ]
            
            risk_df = pd.DataFrame(failure_risks)
            
            # Color code risks
            def risk_color(risk):
                colors = {'Low': '🟢', 'Medium': '🟡', 'High': '🔴', 'Critical': '🔴'}
                return colors.get(risk, '🔵')
            
            risk_df['Risk Status'] = risk_df['Risk'].apply(risk_color)
            
            st.dataframe(risk_df[['Component', 'Risk Status', 'Risk', 'Probability', 'Impact']], 
                        use_container_width=True)
        
        else:
            st.warning("🔒 Predictive analytics is currently disabled")
            st.info("Enable predictive alerts in the sidebar to see trend analysis and capacity planning insights.")
    
    # =================== Alerts Tab ===================
    with tab7:
        st.header("🚨 Intelligent Alert Management")
        
        # Simulated alerts for demo
        demo_alerts = [
            {
                'timestamp': datetime.now() - timedelta(minutes=5),
                'severity': 'critical',
                'source': 'CloudWatch',
                'instance': 'sql-server-prod-1',
                'message': 'High CPU utilization detected (92%)',
                'auto_remediation': 'Enabled'
            },
            {
                'timestamp': datetime.now() - timedelta(minutes=15),
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
        
        # Alert summary
        col1, col2, col3, col4 = st.columns(4)
        
        critical_alerts = [a for a in demo_alerts if a['severity'] == 'critical']
        warning_alerts = [a for a in demo_alerts if a['severity'] == 'warning']
        info_alerts = [a for a in demo_alerts if a['severity'] == 'info']
        
        with col1:
            st.metric("🔴 Critical", len(critical_alerts))
        
        with col2:
            st.metric("🟡 Warning", len(warning_alerts))
        
        with col3:
            st.metric("🔵 Info", len(info_alerts))
        
        with col4:
            auto_remediated = [a for a in demo_alerts if a['auto_remediation'] == 'Enabled']
            st.metric("🤖 Auto-Remediated", len(auto_remediated))
        
        st.markdown("---")
        
        # Alert list
        st.subheader("📋 Recent Alerts")
        
        for alert in demo_alerts:
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
                    if st.button(f"🔧 Remediate", key=f"remediate_{alert['instance']}"):
                        st.success("Remediation action initiated")
                with col2:
                    if st.button(f"📞 Escalate", key=f"escalate_{alert['instance']}"):
                        st.info("Alert escalated to on-call engineer")
                with col3:
                    if st.button(f"✅ Acknowledge", key=f"ack_{alert['instance']}"):
                        st.info("Alert acknowledged")
        
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
                    max_logs = st.slider("Max logs to display", 10, 100, 50)
                
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
        
        # Alert configuration
        st.markdown("---")
        st.subheader("⚙️ Alert Configuration")
        
        with st.expander("🔧 Configure Alert Thresholds"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.write("**Performance Alerts:**")
                cpu_warning = st.slider("CPU Warning Threshold", 50, 90, 70)
                cpu_critical = st.slider("CPU Critical Threshold", 70, 100, 90)
                memory_warning = st.slider("Memory Warning Threshold", 60, 95, 80)
                memory_critical = st.slider("Memory Critical Threshold", 80, 100, 95)
            
            with col2:
                st.write("**Database Alerts:**")
                backup_overdue = st.slider("Backup Overdue (hours)", 12, 72, 24)
                sync_lag = st.slider("AG Sync Lag Warning (seconds)", 1, 30, 5)
                blocking_threshold = st.slider("Blocking Session Alert", 1, 20, 3)
                
                if st.button("💾 Save Configuration"):
                    st.success("Alert configuration saved")
    
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
                    # Similar memory analysis
                    st.info("Memory analysis would be displayed here with similar trending and statistics")
            
            with metric_tabs[2]:
                # Disk I/O analysis
                st.info("Disk I/O metrics and analysis would be displayed here")
            
            with metric_tabs[3]:
                # Network analysis
                st.info("Network performance metrics would be displayed here")
        
        else:
            st.warning("No performance metrics available. Check CloudWatch configuration.")
    
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
            
            # Key metrics summary
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.markdown("""
                <div class="metric-card">
                    <h3>🎯 System Health</h3>
                    <p><strong>Overall Score:</strong> 87/100</p>
                    <p><strong>Availability:</strong> 99.95%</p>
                    <p><strong>Performance:</strong> Good</p>
                </div>
                """, unsafe_allow_html=True)
            
            with col2:
                st.markdown("""
                <div class="metric-card">
                    <h3>🔧 Maintenance</h3>
                    <p><strong>Auto-Remediated:</strong> 15 issues</p>
                    <p><strong>Manual Actions:</strong> 2 pending</p>
                    <p><strong>Uptime:</strong> 99.95%</p>
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
            st.write("1. **Scale EC2 instances** - CPU utilization consistently above 80%")
            st.write("2. **Optimize backup strategy** - Consider incremental backups for large databases")
            st.write("3. **Review Always On configuration** - Secondary replica showing synchronization delays")
            st.write("4. **Implement automated scaling** - Based on predictive analytics")
            
        elif report_type == "Performance Report":
            st.subheader("📊 Detailed Performance Report")
            
            # Performance summary table
            performance_data = [
                {'Metric': 'Average CPU Usage', 'Current': '68%', 'Target': '<70%', 'Status': '🟢 Good'},
                {'Metric': 'Average Memory Usage', 'Current': '82%', 'Target': '<85%', 'Status': '🟡 Monitor'},
                {'Metric': 'Disk I/O Latency', 'Current': '12ms', 'Target': '<15ms', 'Status': '🟢 Good'},
                {'Metric': 'AG Sync Lag', 'Current': '2.1s', 'Target': '<5s', 'Status': '🟢 Good'},
                {'Metric': 'Backup Success Rate', 'Current': '99.2%', 'Target': '>99%', 'Status': '🟢 Good'}
            ]
            
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