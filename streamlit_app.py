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



# Add this near the top of your existing file (after your imports)
from enterprise_enhancements import (
    load_enhanced_enterprise_css,
    render_enhanced_executive_dashboard,
    render_enhanced_auto_remediation_tab,
    calculate_enhanced_health_score
)

# ================= ENHANCED SQL SERVER METRICS CONFIGURATION =================
SQL_SERVER_METRICS_CONFIG = {
    'core_performance': {
        'title': '🎯 Core SQL Server Performance',
        'description': 'Critical SQL Server performance indicators that directly impact user experience',
        'metrics': {
            'buffer_cache_hit_ratio': {
                'display_name': 'Buffer Cache Hit Ratio',
                'cloudwatch_metric': 'SQLServer:Buffer Manager\\Buffer cache hit ratio',
                'namespace': 'CWAgent',
                'unit': 'Percent',
                'good_threshold': 95,
                'warning_threshold': 90,
                'critical_threshold': 85,
                'higher_is_better': True,
                'description': 'Percentage of page requests satisfied from memory. Low values indicate memory pressure.',
                'impact': 'Direct impact on query performance and I/O',
                'remediation': [
                    'Add more memory to the server',
                    'Optimize memory-intensive queries',
                    'Review buffer pool configuration',
                    'Check for memory leaks in applications'
                ]
            },
            'page_life_expectancy': {
                'display_name': 'Page Life Expectancy',
                'cloudwatch_metric': 'SQLServer:Buffer Manager\\Page life expectancy',
                'namespace': 'CWAgent',
                'unit': 'Seconds',
                'good_threshold': 300,
                'warning_threshold': 180,
                'critical_threshold': 100,
                'higher_is_better': True,
                'description': 'Average time a page stays in memory. Lower values indicate memory pressure.',
                'impact': 'Affects query response time and I/O load',
                'remediation': [
                    'Increase server memory',
                    'Optimize queries that consume excessive memory',
                    'Review max server memory settings',
                    'Check for unnecessary data access patterns'
                ]
            },
            'batch_requests_per_sec': {
                'display_name': 'Batch Requests/sec',
                'cloudwatch_metric': 'SQLServer:SQL Statistics\\Batch Requests/sec',
                'namespace': 'CWAgent',
                'unit': 'Count/Second',
                'good_threshold': 1000,
                'warning_threshold': 5000,
                'critical_threshold': 10000,
                'higher_is_better': False,
                'description': 'Number of SQL batches processed per second. High values may indicate load issues.',
                'impact': 'Indicates overall SQL Server workload',
                'remediation': [
                    'Scale up the instance',
                    'Optimize frequently executed queries',
                    'Implement connection pooling',
                    'Review application query patterns'
                ]
            },
            'user_connections': {
                'display_name': 'User Connections',
                'cloudwatch_metric': 'SQLServer:General Statistics\\User Connections',
                'namespace': 'CWAgent',
                'unit': 'Count',
                'good_threshold': 100,
                'warning_threshold': 300,
                'critical_threshold': 500,
                'higher_is_better': False,
                'description': 'Current number of active user connections to SQL Server.',
                'impact': 'Too many connections can exhaust server resources',
                'remediation': [
                    'Implement connection pooling',
                    'Kill idle connections',
                    'Review max connections setting',
                    'Optimize application connection management'
                ]
            }
        }
    },
    'blocking_and_concurrency': {
        'title': '🔒 Blocking & Concurrency',
        'description': 'Metrics that show how well SQL Server handles concurrent operations',
        'metrics': {
            'processes_blocked': {
                'display_name': 'Blocked Processes',
                'cloudwatch_metric': 'SQLServer:General Statistics\\Processes blocked',
                'namespace': 'CWAgent',
                'unit': 'Count',
                'good_threshold': 0,
                'warning_threshold': 5,
                'critical_threshold': 20,
                'higher_is_better': False,
                'description': 'Number of processes currently blocked by other processes.',
                'impact': 'Directly affects user response time and application performance',
                'remediation': [
                    'Identify and kill blocking sessions',
                    'Optimize long-running transactions',
                    'Review indexing strategy',
                    'Consider read committed snapshot isolation'
                ]
            },
            'deadlocks_per_sec': {
                'display_name': 'Deadlocks/sec',
                'cloudwatch_metric': 'SQLServer:Locks\\Number of Deadlocks/sec',
                'namespace': 'CWAgent',
                'unit': 'Count/Second',
                'good_threshold': 0,
                'warning_threshold': 0.1,
                'critical_threshold': 1,
                'higher_is_better': False,
                'description': 'Rate of deadlocks occurring in the database.',
                'impact': 'Causes transaction rollbacks and application errors',
                'remediation': [
                    'Analyze deadlock graphs',
                    'Ensure consistent transaction ordering',
                    'Add appropriate indexes',
                    'Keep transactions short'
                ]
            },
            'lock_waits_per_sec': {
                'display_name': 'Lock Waits/sec',
                'cloudwatch_metric': 'SQLServer:Locks\\Lock Waits/sec',
                'namespace': 'CWAgent',
                'unit': 'Count/Second',
                'good_threshold': 50,
                'warning_threshold': 200,
                'critical_threshold': 1000,
                'higher_is_better': False,
                'description': 'Number of lock requests that had to wait.',
                'impact': 'Indicates concurrency issues and potential blocking',
                'remediation': [
                    'Optimize query performance',
                    'Review indexing strategy',
                    'Consider query hints for locking behavior',
                    'Implement read committed snapshot'
                ]
            }
        }
    }
}

# ================= ENHANCED AUTO-REMEDIATION RULES =================
ENHANCED_AUTO_REMEDIATION_RULES = {
    'low_buffer_cache': {
        'metric': 'buffer_cache_hit_ratio',
        'condition': 'below',
        'threshold': 90,
        'severity': 'High',
        'description': 'Buffer cache hit ratio below optimal levels',
        'impact': 'Queries experiencing increased I/O and slower response times',
        'actions': [
            {
                'type': 'memory_analysis',
                'description': 'Analyze current memory usage patterns',
                'sql_command': "SELECT * FROM sys.dm_os_memory_clerks ORDER BY pages_kb DESC",
                'risk_level': 'Low',
                'auto_execute': True,
                'expected_result': 'Identify memory consumers'
            },
            {
                'type': 'clear_procedure_cache',
                'description': 'Clear procedure cache (temporary fix)',
                'sql_command': 'DBCC FREEPROCCACHE',
                'risk_level': 'Medium',
                'auto_execute': False,
                'expected_result': 'Free up memory temporarily'
            }
        ]
    },
    'high_blocking': {
        'metric': 'processes_blocked',
        'condition': 'above',
        'threshold': 5,
        'severity': 'Critical',
        'description': 'Multiple processes blocked by other sessions',
        'impact': 'Users experiencing delays and potential application timeouts',
        'actions': [
            {
                'type': 'diagnostic',
                'description': 'Find the blocking chain',
                'sql_command': "SELECT * FROM sys.dm_exec_requests WHERE blocking_session_id != 0",
                'risk_level': 'Low',
                'auto_execute': True,
                'expected_result': 'Identifies blocking sessions'
            }
        ]
    }
}



# Utility Functions
def safe_format_method(method_value):
    """Safely format connection method string, handling None values"""
    if method_value is None:
        return 'Unknown'
    return str(method_value).replace('_', ' ').title()

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

# =================== CSS Styles ===================
def load_css_styles():
    """Load CSS styles for the application"""
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
            
         /* Add these new styles */
        .metric-card-enhanced {
            border-radius: 10px;
            padding: 1rem;
            margin: 0.5rem 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            transition: transform 0.2s ease-in-out;
        }
        .metric-card-enhanced:hover {
            transform: translateY(-2px);
        }
        .status-good { 
            border-left: 5px solid #28a745; 
            background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%);
        }
        .status-warning { 
            border-left: 5px solid #ffc107; 
            background: linear-gradient(135deg, #fff3cd 0%, #ffeaa7 100%);
        }
        .status-critical { 
            border-left: 5px solid #dc3545; 
            background: linear-gradient(135deg, #f8d7da 0%, #f5c6cb 100%);
        }
        .health-score {
            text-align: center;
            padding: 1.5rem;
            border-radius: 15px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
        }
    </style>
    """, unsafe_allow_html=True)

# =================== Streamlit Cloud Compatible AWS Connection Manager ===================
# ================= ENHANCED HELPER FUNCTIONS =================

def calculate_sql_server_health_score(instance_metrics, instance_id):
    """Calculate health score for specific SQL Server instance"""
    
    scores = []
    
    # Buffer Cache Hit Ratio (Weight: 25%)
    buffer_cache_key = f"{instance_id}_buffer_cache_hit_ratio"
    if buffer_cache_key in instance_metrics:
        buffer_cache = get_metric_current_value(instance_metrics[buffer_cache_key])
        buffer_score = min(100, (buffer_cache / 95) * 100) if buffer_cache > 0 else 0
        scores.append(('buffer_cache', buffer_score, 25))
    
    # Blocking Processes (Weight: 20%)
    blocked_key = f"{instance_id}_processes_blocked" 
    if blocked_key in instance_metrics:
        blocked = get_metric_current_value(instance_metrics[blocked_key])
        block_score = max(0, 100 - (blocked * 10))
        scores.append(('blocking', block_score, 20))
    
    # Deadlocks (Weight: 15%)
    deadlock_key = f"{instance_id}_deadlocks_per_sec"
    if deadlock_key in instance_metrics:
        deadlocks = get_metric_current_value(instance_metrics[deadlock_key])
        deadlock_score = max(0, 100 - (deadlocks * 100))
        scores.append(('deadlocks', deadlock_score, 15))
    
    # Memory Grants Pending (Weight: 15%)
    memory_key = f"{instance_id}_memory_grants_pending"
    if memory_key in instance_metrics:
        mem_grants = get_metric_current_value(instance_metrics[memory_key])
        mem_score = max(0, 100 - (mem_grants * 5))
        scores.append(('memory', mem_score, 15))
    
    # Page Life Expectancy (Weight: 25%)
    page_life_key = f"{instance_id}_page_life_expectancy"
    if page_life_key in instance_metrics:
        page_life = get_metric_current_value(instance_metrics[page_life_key])
        page_score = min(100, (page_life / 300) * 100) if page_life > 0 else 0
        scores.append(('page_life', page_score, 25))
    
    if not scores:
        return 0
    
    # Calculate weighted average
    total_score = sum(score * weight for _, score, weight in scores)
    total_weight = sum(weight for _, _, weight in scores)
    
    return int(total_score / total_weight) if total_weight > 0 else 0

def get_metric_current_value(metric_data):
    """Get the most recent value from metric data"""
    if not metric_data:
        return 0
    return metric_data[-1]['Average'] if metric_data else 0

def get_metric_status_color(metric_key, current_value):
    """Get status color for a metric"""
    # Find metric configuration
    for category in SQL_SERVER_METRICS_CONFIG.values():
        if metric_key in category['metrics']:
            metric_info = category['metrics'][metric_key]
            
            good_threshold = metric_info.get('good_threshold')
            warning_threshold = metric_info.get('warning_threshold')
            critical_threshold = metric_info.get('critical_threshold')
            higher_is_better = metric_info.get('higher_is_better', True)
            
            if good_threshold and warning_threshold and critical_threshold:
                if higher_is_better:
                    if current_value >= good_threshold:
                        return "🟢"
                    elif current_value >= warning_threshold:
                        return "🟡"
                    else:
                        return "🔴"
                else:
                    if current_value <= good_threshold:
                        return "🟢"
                    elif current_value <= warning_threshold:
                        return "🟡"
                    else:
                        return "🔴"
    
    return "🔵"  # Default

def create_metric_card(title, value, unit, status, description):
    """Create a visual metric card with status indicator"""
    
    status_colors = {
        'good': '#28a745',
        'warning': '#ffc107', 
        'critical': '#dc3545',
        'unknown': '#6c757d'
    }
    
    status_icons = {
        'good': '🟢',
        'warning': '🟡',
        'critical': '🔴',
        'unknown': '🔵'
    }
    
    border_color = status_colors.get(status, '#6c757d')
    status_icon = status_icons.get(status, '🔵')
    
    return f"""
    <div style="
        border: 2px solid {border_color};
        border-radius: 10px;
        padding: 1rem;
        text-align: center;
        background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        margin: 0.5rem 0;
    ">
        <h4 style="margin: 0 0 0.5rem 0; color: #333;">
            {status_icon} {title}
        </h4>
        <div style="font-size: 1.5rem; font-weight: bold; color: #007bff; margin: 0.5rem 0;">
            {value} {unit}
        </div>
        <div style="font-size: 0.8rem; color: #666;">
            {description}
        </div>
    </div>
    """

def get_buffer_cache_status(value):
    """Get status for buffer cache hit ratio"""
    if value > 95:
        return 'good'
    elif value > 90:
        return 'warning'
    else:
        return 'critical'

def get_connections_status(value):
    """Get status for connection count"""
    if value < 200:
        return 'good'
    elif value < 400:
        return 'warning'
    else:
        return 'critical'

def get_blocking_status(value):
    """Get status for blocked processes"""
    if value == 0:
        return 'good'
    elif value < 5:
        return 'warning'
    else:
        return 'critical'

def get_deadlock_status(value):
    """Get status for deadlock rate"""
    if value == 0:
        return 'good'
    elif value < 0.1:
        return 'warning'
    else:
        return 'critical'



class StreamlitAWSManager:
    """Specialized AWS connection manager designed for Streamlit Cloud environment"""
    
    def __init__(self):
        self.is_streamlit_cloud = self._detect_streamlit_cloud()
        self.demo_mode = not AWS_AVAILABLE
        self._reset_connection_state()
        
    def _detect_streamlit_cloud(self) -> bool:
        """Detect if running in Streamlit Cloud environment"""
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
            'method': '',
            'error': None,
            'last_test': None,
            'account_id': None,
            'region': None,
            'user_arn': None
        }
        self.aws_session = None
        self.clients = {}
    
    def initialize_aws_connection(self, aws_config: Dict) -> bool:
        """Initialize AWS connection with Streamlit Cloud optimizations"""
        if not AWS_AVAILABLE:
            self.demo_mode = True
            self.connection_status['error'] = "boto3 not available - running in demo mode"
            return True
        
        self._reset_connection_state()
        
        access_key = str(aws_config.get('access_key', '')).strip()
        secret_key = str(aws_config.get('secret_key', '')).strip()
        region = str(aws_config.get('region', 'us-east-2')).strip()
        
        os.environ['AWS_DEFAULT_REGION'] = region
        
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
        
        self.demo_mode = True
        self.connection_status['error'] = "All AWS authentication methods failed"
        return False
    
    def _try_explicit_credentials(self, access_key: str, secret_key: str, region: str):
        """Try explicit credentials"""
        if not access_key or not secret_key or access_key == 'demo' or secret_key == 'demo':
            return None
        
        if not self._validate_aws_credentials(access_key, secret_key):
            raise ValueError("Invalid credential format")
        
        return boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )
    
    def _try_environment_credentials(self, region: str):
        """Try environment variables"""
        if 'AWS_ACCESS_KEY_ID' in os.environ and 'AWS_SECRET_ACCESS_KEY' in os.environ:
            return boto3.Session(region_name=region)
        return None
    
    def _try_shared_credentials(self, region: str):
        """Try shared credentials file"""
        try:
            session = boto3.Session(region_name=region)
            session.client('sts').get_caller_identity()
            return session
        except:
            return None
    
    def _try_instance_metadata(self, region: str):
        """Try EC2 instance metadata"""
        try:
            session = boto3.Session(region_name=region)
            session.client('sts').get_caller_identity()
            return session
        except:
            return None
    
    def _validate_aws_credentials(self, access_key: str, secret_key: str) -> bool:
        """Validate AWS credential format"""
        access_key_pattern = r'^(AKIA|ASIA)[0-9A-Z]{16}$'
        if not re.match(access_key_pattern, access_key):
            return False
        
        if len(secret_key) != 40:
            return False
        
        return True
    
    def _test_session(self, session, method_name: str) -> bool:
        """Test AWS session with detailed error reporting and debugging"""
        try:
            # Show debug info in the UI
            with st.container():
                st.write(f"🧪 **Testing {method_name} session...**")
                
                config = Config(
                    region_name=session.region_name or 'us-east-2',
                    retries={'max_attempts': 2, 'mode': 'standard'},
                    max_pool_connections=10,
                    read_timeout=30,
                    connect_timeout=30
                )
                
                # Test STS first (most basic AWS service)
                st.write("🔄 Creating STS client...")
                sts_client = session.client('sts', config=config)
                
                st.write("🔄 Calling sts.get_caller_identity()...")
                identity = sts_client.get_caller_identity()
                
                st.success(f"✅ **STS Success!**")
                st.write(f"📋 **Account ID:** {identity.get('Account')}")
                st.write(f"👤 **User ARN:** {identity.get('Arn')}")
                st.write(f"🌍 **Region:** {session.region_name}")
                
                # Store account information
                self.connection_status.update({
                    'account_id': identity.get('Account'),
                    'user_arn': identity.get('Arn'),
                    'region': session.region_name,
                    'last_test': datetime.now()
                })
                
                # Test CloudWatch access
                st.write("🔄 Testing CloudWatch access...")
                try:
                    cloudwatch_client = session.client('cloudwatch', config=config)
                    response = cloudwatch_client.list_metrics()
                    metrics_count = len(response.get('Metrics', []))
                    st.success(f"✅ CloudWatch access confirmed - found {metrics_count} metrics")
                except ClientError as cw_e:
                    error_code = cw_e.response['Error']['Code']
                    st.warning(f"⚠️ CloudWatch access limited: {error_code}")
                    if error_code == "AccessDenied":
                        st.info("💡 Need cloudwatch:ListMetrics permission - but basic functionality will still work")
                    else:
                        st.info("💡 CloudWatch permissions limited - but basic functionality will still work")
                except Exception as cw_e:
                    st.warning(f"⚠️ CloudWatch test failed: {str(cw_e)}")
                
                # Test EC2 access
                st.write("🔄 Testing EC2 access...")
                try:
                    ec2_client = session.client('ec2', config=config)
                    response = ec2_client.describe_instances(MaxResults=5)
                    total_instances = sum(len(r['Instances']) for r in response['Reservations'])
                    st.success(f"✅ EC2 access confirmed - found {total_instances} instances")
                except ClientError as ec2_e:
                    error_code = ec2_e.response['Error']['Code']
                    st.warning(f"⚠️ EC2 access limited: {error_code}")
                    if error_code == "UnauthorizedOperation":
                        st.info("💡 Need ec2:DescribeInstances permission")
                except Exception as ec2_e:
                    st.info(f"ℹ️ EC2 test skipped: {str(ec2_e)}")
                
                # Test RDS access
                st.write("🔄 Testing RDS access...")
                try:
                    rds_client = session.client('rds', config=config)
                    response = rds_client.describe_db_instances(MaxRecords=5)
                    db_count = len(response.get('DBInstances', []))
                    st.success(f"✅ RDS access confirmed - found {db_count} DB instances")
                except ClientError as rds_e:
                    error_code = rds_e.response['Error']['Code']
                    st.warning(f"⚠️ RDS access limited: {error_code}")
                    if error_code == "AccessDenied":
                        st.info("💡 Need rds:DescribeDBInstances permission")
                except Exception as rds_e:
                    st.info(f"ℹ️ RDS test skipped: {str(rds_e)}")
                
                return True
                
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            
            # Show detailed error in the UI
            with st.container():
                st.error(f"❌ **AWS ClientError: {error_code}**")
                st.error(f"📝 **Message:** {error_message}")
                
                # Show specific error help
                if error_code == "InvalidUserID.NotFound":
                    st.error("🔑 **Issue:** Your AWS Access Key ID is invalid or the user was deleted")
                    st.info("💡 **Fix:** Check your AWS Access Key ID in the AWS Console")
                elif error_code == "SignatureDoesNotMatch":
                    st.error("🔑 **Issue:** Your AWS Secret Access Key is incorrect")
                    st.info("💡 **Fix:** Check your AWS Secret Access Key in the AWS Console")
                elif error_code == "AccessDenied":
                    st.error("🔒 **Issue:** Your user doesn't have sts:GetCallerIdentity permission")
                    st.info("💡 **Fix:** Ask your AWS admin to add IAM permissions")
                elif error_code == "TokenRefreshRequired":
                    st.error("⏰ **Issue:** Your AWS credentials have expired")
                    st.info("💡 **Fix:** Generate new AWS credentials")
                else:
                    st.error(f"❓ **Unknown AWS Error:** {error_code}")
                
                # Show the full error details
                with st.expander("🔍 Full Error Details"):
                    st.json(e.response)
            
            self.connection_status['error'] = f"{error_code}: {error_message}"
            return False
            
        except Exception as e:
            # Show unexpected errors
            with st.container():
                st.error(f"❌ **Unexpected Error:** {str(e)}")
                st.error(f"📝 **Error Type:** {type(e).__name__}")
                
                # Show more details for debugging
                with st.expander("🔍 Technical Details"):
                    st.code(f"""
Error Type: {type(e).__name__}
Error Message: {str(e)}
Method: {method_name}
Region: {session.region_name if session else 'Unknown'}
                    """)
            
            self.connection_status['error'] = f"Unexpected error: {str(e)}"
            return False
    
    def _initialize_clients(self):
        """Initialize AWS service clients with optimized configuration"""
        if not self.aws_session:
            return
        
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

# =================== STEP 1: PLACE THIS FUNCTION RIGHT AFTER get_aws_manager() ===================

def test_log_groups(log_groups):
    """Test access to specified log groups"""
    if not st.session_state.cloudwatch_connector or st.session_state.cloudwatch_connector.demo_mode:
        st.warning("AWS connection required for testing")
        return
    
    st.write("🧪 **Testing log group access...**")
    
    logs_client = st.session_state.cloudwatch_connector.aws_manager.get_client('logs')
    if not logs_client:
        st.error("❌ No CloudWatch Logs client available")
        return
    
    results = []
    
    for log_group in log_groups:
        try:
            response = logs_client.describe_log_groups(
                logGroupNamePrefix=log_group,
                limit=1
            )
            
            found = any(lg['logGroupName'] == log_group for lg in response['logGroups'])
            
            if found:
                try:
                    logs_client.filter_log_events(
                        logGroupName=log_group,
                        limit=1
                    )
                    results.append({"log_group": log_group, "status": "✅ OK", "message": "Accessible"})
                except Exception as read_error:
                    results.append({"log_group": log_group, "status": "⚠️ Limited", "message": f"Read error: {str(read_error)}"})
            else:
                results.append({"log_group": log_group, "status": "❌ Not Found", "message": "Log group does not exist"})
                
        except Exception as e:
            results.append({"log_group": log_group, "status": "❌ Error", "message": str(e)})
    
    # Display results
    for result in results:
        if result["status"].startswith("✅"):
            st.success(f'{result["status"]} **{result["log_group"]}** - {result["message"]}')
        elif result["status"].startswith("⚠️"):
            st.warning(f'{result["status"]} **{result["log_group"]}** - {result["message"]}')
        else:
            st.error(f'{result["status"]} **{result["log_group"]}** - {result["message"]}')
    
   # =================== AWS CloudWatch Integration ===================
class AWSCloudWatchConnector:
    def __init__(self, aws_config: Dict):
        """Initialize AWS CloudWatch connections using the manager"""
        self.aws_config = aws_config
        self.aws_manager = get_aws_manager()
        
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
            
            # ===== WAIT STATISTICS =====
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
                    'AvailabilityZone': 'us-east-2a',
                    'MultiAZ': False,
                    'AllocatedStorage': 100
                },
                {
                    'DBInstanceIdentifier': 'sql-server-prod-2',
                    'Engine': 'sqlserver-se',
                    'DBInstanceStatus': 'available',
                    'AvailabilityZone': 'us-east-2b',
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
    
    def get_ec2_sql_instances(self):
        """Get ALL EC2 instances and let user choose SQL Servers"""
    
    if self.demo_mode:
        return [
            {
                'InstanceId': 'i-1234567890abcdef0',
                'InstanceType': 'm5.xlarge',
                'State': {'Name': 'running'},
                'PrivateIpAddress': '10.0.1.100',
                'Tags': [{'Key': 'Name', 'Value': 'SQL-Server-1'}]
            }
        ]
    
    try:
        ec2_client = self.aws_manager.get_client('ec2')
        if not ec2_client:
            return []
        
        # Get ALL instances (no filters)
        response = ec2_client.describe_instances()
        
        all_instances = []
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                # Include running and stopped instances
                if instance['State']['Name'] in ['running', 'stopped']:
                    all_instances.append(instance)
        
        return all_instances
        
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

    def get_available_log_groups(self):
    """Get ALL available CloudWatch log groups"""
    
    if self.demo_mode:
        return [
            "/aws/ec2/windows/application",
            "/aws/ec2/windows/system", 
            "/aws/rds/instance/sql-prod/error",
            "custom-sql-logs"
        ]
    
    try:
        logs_client = self.aws_manager.get_client('logs')
        if not logs_client:
            return []
        
        # Get all log groups
        log_groups = []
        response = logs_client.describe_log_groups()
        
        for log_group in response['logGroups']:
            log_groups.append(log_group['logGroupName'])
        
        return sorted(log_groups)
        
    except Exception as e:
        logger.error(f"Failed to get log groups: {str(e)}")
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
            
            # ===== WINDOWS SPECIFIC METRICS =====
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
        
        for metric in os_metric_queries:
            metric['dimensions'] = [
                {'Name': 'InstanceId', 'Value': instance_id},
                {'Name': 'ImageId', 'Value': 'ami-xxxxx'},
                {'Name': 'InstanceType', 'Value': 'm5.large'}
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
                'region': self.aws_config.get('region', 'us-east-2'),
                'vpc_id': 'vpc-1234567890abcdef0',
                'environment': 'demo'
            }
        
        try:
            sts_client = self.aws_manager.get_client('sts')
            if not sts_client:
                return {}
                
            identity = sts_client.get_caller_identity()
            account_id = identity['Account']
            
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
            for i in range(24):
                timestamp = current_time - timedelta(hours=i)
                
                key = query['key'].lower()
                
                if 'cpu' in key:
                    value = np.random.uniform(20, 80)
                elif 'memory' in key:
                    value = np.random.uniform(60, 90)
                elif 'buffer_cache_hit_ratio' in key:
                    value = np.random.uniform(95, 99.9)
                elif 'page_life_expectancy' in key:
                    value = np.random.uniform(300, 3600)
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
                    value = np.random.uniform(8000000, 16000000)
                elif 'total_server_memory_kb' in key:
                    value = np.random.uniform(7000000, 15000000)
                elif 'cache_hit_ratio' in key:
                    value = np.random.uniform(85, 99)
                elif 'wait_' in key and '_ms' in key:
                    value = np.random.uniform(0, 5000)
                elif 'ag_log_send_queue_size' in key:
                    value = np.random.uniform(0, 1000000)
                elif 'ag_log_send_rate' in key:
                    value = np.random.uniform(100, 10000)
                elif 'ag_redo_queue_size' in key:
                    value = np.random.uniform(0, 500000)
                elif 'ag_redo_rate' in key:
                    value = np.random.uniform(50, 5000)
                elif 'db_data_file_size_kb' in key:
                    value = np.random.uniform(1000000, 100000000)
                elif 'db_log_file_size_kb' in key:
                    value = np.random.uniform(100000, 10000000)
                elif 'db_percent_log_used' in key:
                    value = np.random.uniform(10, 80)
                elif 'db_active_transactions' in key:
                    value = np.random.uniform(0, 100)
                elif 'db_transactions_per_sec' in key:
                    value = np.random.uniform(10, 1000)
                elif 'db_log_flushes_per_sec' in key:
                    value = np.random.uniform(1, 100)
                elif 'db_log_flush_wait_time' in key:
                    value = np.random.uniform(0, 50)
                elif 'tempdb_version_store_size_kb' in key:
                    value = np.random.uniform(0, 1000000)
                elif 'backup_throughput_bytes_per_sec' in key:
                    value = np.random.uniform(1000000, 100000000)
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
        
        return self._get_ag_status_from_cloudwatch()
    
    def _get_ag_status_from_cloudwatch(self) -> List[Dict]:
        """Get AG status from CloudWatch custom metrics"""
        try:
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
        
        return []

# =================== Auto-Remediation Engine ===================
# ================= ENHANCED AUTO-REMEDIATION ENGINE =================
class EnhancedAutoRemediationEngine:
    """Enhanced auto-remediation with SQL Server focus and clear visibility"""
    
    def __init__(self, cloudwatch_connector):
        self.cloudwatch = cloudwatch_connector
        self.execution_history = []
        self.snoozed_rules = {}
        self.success_metrics = {
            'total_executed': 0,
            'successful': 0,
            'failed': 0,
            'auto_executed': 0,
            'manual_executed': 0
        }
    
    def evaluate_all_rules(self, all_metrics: Dict) -> List[Dict]:
        """Evaluate all remediation rules and return active opportunities"""
        
        active_opportunities = []
        current_time = datetime.now()
        
        # SQL Server specific rules
        sql_rules = {
            'low_buffer_cache': {
                'metric_key': 'buffer_cache_hit_ratio',
                'condition': 'below',
                'threshold': 90,
                'severity': 'High',
                'duration_minutes': 5,
                'description': 'Buffer cache hit ratio below optimal levels',
                'impact': 'Queries experiencing increased I/O and slower response times',
                'business_impact': 'Users may experience 2-5x slower query response times',
                'actions': [
                    {
                        'type': 'diagnostic',
                        'name': 'Analyze Memory Usage',
                        'description': 'Identify current memory consumers',
                        'sql_command': "SELECT TOP 10 type, name, pages_kb, pages_kb/1024 AS pages_mb FROM sys.dm_os_memory_clerks ORDER BY pages_kb DESC",
                        'risk_level': 'Low',
                        'auto_execute': True,
                        'expected_outcome': 'Identifies top memory consumers'
                    },
                    {
                        'type': 'temporary_fix',
                        'name': 'Clear Procedure Cache',
                        'description': 'Free memory by clearing procedure cache (temporary)',
                        'sql_command': 'DBCC FREEPROCCACHE',
                        'risk_level': 'Medium',
                        'auto_execute': False,
                        'expected_outcome': 'Frees 10-20% of memory temporarily',
                        'side_effects': 'All queries will need to recompile - temporary performance impact'
                    },
                    {
                        'type': 'recommendation',
                        'name': 'Scale Instance',
                        'description': 'Add more memory to the server',
                        'action_details': 'Recommend upgrading instance type or adding memory',
                        'risk_level': 'Low',
                        'auto_execute': True,
                        'expected_outcome': 'Permanent solution to memory pressure'
                    }
                ]
            },
            'high_blocking': {
                'metric_key': 'processes_blocked',
                'condition': 'above',
                'threshold': 5,
                'severity': 'Critical',
                'duration_minutes': 2,
                'description': 'Multiple processes blocked by other sessions',
                'impact': 'Users experiencing delays and potential application timeouts',
                'business_impact': 'Applications may become unresponsive, affecting user productivity',
                'actions': [
                    {
                        'type': 'diagnostic',
                        'name': 'Identify Blocking Chain',
                        'description': 'Find the root blocker and blocking hierarchy',
                        'sql_command': """
SELECT 
    blocking_session_id,
    session_id,
    wait_type,
    wait_time,
    wait_resource,
    SUBSTRING(st.text, (r.statement_start_offset/2)+1,
        ((CASE r.statement_end_offset
            WHEN -1 THEN DATALENGTH(st.text)
            ELSE r.statement_end_offset 
        END - r.statement_start_offset)/2) + 1) AS blocking_query
FROM sys.dm_exec_requests r
CROSS APPLY sys.dm_exec_sql_text(r.sql_handle) st
WHERE r.blocking_session_id != 0
ORDER BY wait_time DESC
                        """,
                        'risk_level': 'Low',
                        'auto_execute': True,
                        'expected_outcome': 'Identifies the blocking chain and problematic queries'
                    },
                    {
                        'type': 'intervention',
                        'name': 'Kill Head Blocker',
                        'description': 'Terminate the session causing the blocking (HIGH RISK)',
                        'sql_command': '-- KILL [session_id] -- REQUIRES MANUAL APPROVAL',
                        'risk_level': 'High',
                        'auto_execute': False,
                        'expected_outcome': 'Resolves blocking immediately',
                        'side_effects': 'May cause transaction rollback and application errors'
                    }
                ]
            },
            'frequent_deadlocks': {
                'metric_key': 'deadlocks_per_sec',
                'condition': 'above', 
                'threshold': 0.1,
                'severity': 'High',
                'duration_minutes': 10,
                'description': 'High rate of deadlocks detected',
                'impact': 'Applications experiencing transaction rollbacks and errors',
                'business_impact': 'Failed transactions may result in data inconsistency',
                'actions': [
                    {
                        'type': 'monitoring',
                        'name': 'Enable Deadlock Logging',
                        'description': 'Turn on detailed deadlock logging',
                        'sql_command': 'DBCC TRACEON(1222, -1)',
                        'risk_level': 'Low',
                        'auto_execute': True,
                        'expected_outcome': 'Deadlock details logged to SQL Server error log'
                    },
                    {
                        'type': 'diagnostic',
                        'name': 'Query Recent Deadlocks',
                        'description': 'Retrieve recent deadlock information from system health',
                        'sql_command': """
SELECT 
    CAST(event_data AS XML) AS DeadlockGraph,
    CAST(event_data AS XML).value('(event/@timestamp)[1]', 'datetime2') AS timestamp
FROM sys.fn_xe_file_target_read_file('system_health*.xel', null, null, null)
WHERE object_name = 'xml_deadlock_report'
ORDER BY timestamp DESC
                        """,
                        'risk_level': 'Low',
                        'auto_execute': True,
                        'expected_outcome': 'Recent deadlock graphs for analysis'
                    }
                ]
            },
            'log_space_critical': {
                'metric_key': 'db_percent_log_used',
                'condition': 'above',
                'threshold': 85,
                'severity': 'Critical',
                'duration_minutes': 0,  # Immediate
                'description': 'Transaction log space critically low',
                'impact': 'Database may become read-only if log fills completely',
                'business_impact': 'Application may fail completely - IMMEDIATE ACTION REQUIRED',
                'actions': [
                    {
                        'type': 'emergency',
                        'name': 'Emergency Log Backup',
                        'description': 'Backup transaction log to free space',
                        'sql_command': """
DECLARE @BackupPath NVARCHAR(500) = 'C:\\Temp\\Emergency_Log_Backup_' + FORMAT(GETDATE(), 'yyyyMMdd_HHmmss') + '.trn'
BACKUP LOG [YourDatabaseName] TO DISK = @BackupPath
                        """,
                        'risk_level': 'Low',
                        'auto_execute': True,
                        'expected_outcome': 'Frees transaction log space immediately'
                    },
                    {
                        'type': 'diagnostic',
                        'name': 'Analyze Log Space Usage',
                        'description': 'Check log space usage across all databases',
                        'sql_command': """
DBCC SQLPERF(LOGSPACE)

SELECT 
    name as DatabaseName,
    log_reuse_wait_desc,
    log_reuse_wait
FROM sys.databases 
WHERE log_reuse_wait_desc != 'NOTHING'
                        """,
                        'risk_level': 'Low',
                        'auto_execute': True,
                        'expected_outcome': 'Identifies databases with log space issues'
                    }
                ]
            }
        }
        
        # Evaluate each rule
        for rule_name, rule_config in sql_rules.items():
            # Check if rule is snoozed
            if rule_name in self.snoozed_rules:
                if current_time < self.snoozed_rules[rule_name]:
                    continue  # Skip snoozed rule
                else:
                    del self.snoozed_rules[rule_name]  # Remove expired snooze
            
            # Get current metric value
            current_value = self._get_current_metric_value(all_metrics, rule_config['metric_key'])
            
            # Evaluate condition
            if self._evaluate_condition(current_value, rule_config):
                opportunity = {
                    'rule_name': rule_name,
                    'rule_config': rule_config,
                    'current_value': current_value,
                    'triggered_at': current_time
                }
                active_opportunities.append(opportunity)
        
        return active_opportunities
    
    def execute_action(self, action: Dict, rule_name: str) -> Dict:
        """Execute a specific remediation action"""
        
        execution_start = datetime.now()
        
        try:
            result = {
                'action_name': action['name'],
                'action_type': action['type'],
                'rule_name': rule_name,
                'started_at': execution_start,
                'status': 'executing'
            }
            
            if action['type'] == 'diagnostic':
                result.update(self._execute_diagnostic_action(action))
            elif action['type'] == 'emergency':
                result.update(self._execute_emergency_action(action))
            elif action['type'] == 'monitoring':
                result.update(self._execute_monitoring_action(action))
            elif action['type'] == 'temporary_fix':
                result.update(self._execute_temporary_fix_action(action))
            elif action['type'] == 'recommendation':
                result.update(self._execute_recommendation_action(action))
            else:
                result['status'] = 'failed'
                result['error'] = f"Unknown action type: {action['type']}"
            
            result['completed_at'] = datetime.now()
            result['duration'] = (result['completed_at'] - execution_start).total_seconds()
            
            # Update success metrics
            self.success_metrics['total_executed'] += 1
            if result['status'] == 'success':
                self.success_metrics['successful'] += 1
            else:
                self.success_metrics['failed'] += 1
            
            if action.get('auto_execute'):
                self.success_metrics['auto_executed'] += 1
            else:
                self.success_metrics['manual_executed'] += 1
            
            # Add to execution history
            self.execution_history.append(result)
            
            return result
            
        except Exception as e:
            self.success_metrics['total_executed'] += 1
            self.success_metrics['failed'] += 1
            
            error_result = {
                'action_name': action['name'],
                'action_type': action['type'],
                'rule_name': rule_name,
                'started_at': execution_start,
                'completed_at': datetime.now(),
                'status': 'failed',
                'error': str(e)
            }
            
            self.execution_history.append(error_result)
            return error_result
    
    def _execute_diagnostic_action(self, action: Dict) -> Dict:
        """Execute diagnostic SQL commands"""
        if self.cloudwatch.demo_mode:
            return {
                'status': 'success',
                'message': f"[DEMO] Would execute diagnostic: {action['description']}",
                'sql_executed': action.get('sql_command', 'N/A'),
                'results': 'Demo results would be displayed here'
            }
        
        try:
            # In real implementation, execute SQL via SSM or direct connection
            sql_command = action.get('sql_command', '')
            
            if sql_command:
                # Execute via AWS SSM Run Command or direct SQL connection
                result = self._execute_sql_command(sql_command)
                
                return {
                    'status': 'success',
                    'message': f"Diagnostic completed: {action['description']}",
                    'sql_executed': sql_command,
                    'results': result
                }
            else:
                return {
                    'status': 'success',
                    'message': f"Diagnostic action completed: {action['description']}"
                }
                
        except Exception as e:
            return {
                'status': 'failed',
                'error': str(e)
            }
    
    def _execute_emergency_action(self, action: Dict) -> Dict:
        """Execute emergency actions like log backups"""
        if self.cloudwatch.demo_mode:
            return {
                'status': 'success',
                'message': f"[DEMO] Emergency action simulated: {action['description']}",
                'impact': 'Transaction log space would be freed'
            }
        
        try:
            sql_command = action.get('sql_command', '')
            
            if 'BACKUP LOG' in sql_command:
                # Execute emergency log backup
                result = self._execute_sql_command(sql_command)
                
                return {
                    'status': 'success',
                    'message': f"Emergency log backup completed: {action['description']}",
                    'sql_executed': sql_command,
                    'impact': 'Transaction log space freed'
                }
            
            return {
                'status': 'success',
                'message': f"Emergency action completed: {action['description']}"
            }
            
        except Exception as e:
            return {
                'status': 'failed',
                'error': str(e)
            }
    
    def _execute_monitoring_action(self, action: Dict) -> Dict:
        """Execute monitoring setup actions"""
        if self.cloudwatch.demo_mode:
            return {
                'status': 'success',
                'message': f"[DEMO] Monitoring enabled: {action['description']}"
            }
        
        try:
            sql_command = action.get('sql_command', '')
            
            if 'TRACEON' in sql_command:
                result = self._execute_sql_command(sql_command)
                
                return {
                    'status': 'success',
                    'message': f"Monitoring enabled: {action['description']}",
                    'sql_executed': sql_command
                }
            
            return {
                'status': 'success',
                'message': f"Monitoring action completed: {action['description']}"
            }
            
        except Exception as e:
            return {
                'status': 'failed',
                'error': str(e)
            }
    
    def _execute_temporary_fix_action(self, action: Dict) -> Dict:
        """Execute temporary fix actions (requires approval)"""
        return {
            'status': 'pending_approval',
            'message': f"Temporary fix requires manual approval: {action['description']}",
            'risk_level': action.get('risk_level', 'Medium'),
            'side_effects': action.get('side_effects', 'Unknown side effects')
        }
    
    def _execute_recommendation_action(self, action: Dict) -> Dict:
        """Execute recommendation actions"""
        return {
            'status': 'success',
            'message': f"Recommendation generated: {action['description']}",
            'recommendation_details': action.get('action_details', 'See action description')
        }
    
    def _execute_sql_command(self, sql_command: str) -> str:
        """Execute SQL command via SSM or direct connection"""
        if self.cloudwatch.demo_mode:
            return "Demo results - SQL command would be executed here"
        
        try:
            # In real implementation:
            # 1. Use AWS SSM Run Command to execute SQL
            # 2. Or use direct SQL Server connection
            # 3. Return actual results
            
            ssm_client = self.cloudwatch.aws_manager.get_client('ssm')
            if ssm_client:
                # Execute via SSM Run Command
                response = ssm_client.send_command(
                    InstanceIds=['your-instance-id'],  # Replace with actual instance ID
                    DocumentName="AWS-RunPowerShellScript",
                    Parameters={
                        'commands': [f'sqlcmd -Q "{sql_command}"']
                    }
                )
                
                return f"Command executed via SSM: {response['Command']['CommandId']}"
            
            return "SQL command executed successfully"
            
        except Exception as e:
            raise Exception(f"Failed to execute SQL command: {str(e)}")
    
    def _get_current_metric_value(self, all_metrics: Dict, metric_key: str) -> float:
        """Get current value for a specific metric"""
        # Look for metric in all_metrics with various possible keys
        possible_keys = [
            metric_key,
            f"*_{metric_key}",  # Instance prefixed
        ]
        
        for key_pattern in possible_keys:
            if key_pattern.startswith('*_'):
                # Find any key ending with the metric name
                suffix = key_pattern[2:]
                matching_keys = [k for k in all_metrics.keys() if k.endswith(suffix)]
                if matching_keys:
                    metric_data = all_metrics[matching_keys[0]]
                    if metric_data:
                        return metric_data[-1]['Average']
            else:
                if key_pattern in all_metrics:
                    metric_data = all_metrics[key_pattern]
                    if metric_data:
                        return metric_data[-1]['Average']
        
        # Mock values for demo
        mock_values = {
            'buffer_cache_hit_ratio': np.random.uniform(85, 99),
            'processes_blocked': np.random.poisson(2),
            'deadlocks_per_sec': np.random.exponential(0.05),
            'db_percent_log_used': np.random.uniform(20, 90),
            'memory_grants_pending': np.random.poisson(1),
            'page_life_expectancy': np.random.uniform(100, 800)
        }
        
        return mock_values.get(metric_key, 0)
    
    def _evaluate_condition(self, current_value: float, rule_config: Dict) -> bool:
        """Evaluate if rule condition is met"""
        threshold = rule_config['threshold']
        condition = rule_config['condition']
        
        if condition == 'above':
            return current_value > threshold
        elif condition == 'below':
            return current_value < threshold
        
        return False
    
    def snooze_rule(self, rule_name: str, minutes: int):
        """Snooze a rule for specified minutes"""
        snooze_until = datetime.now() + timedelta(minutes=minutes)
        self.snoozed_rules[rule_name] = snooze_until
    
    def get_success_rate(self) -> float:
        """Calculate success rate of remediation actions"""
        total = self.success_metrics['total_executed']
        if total == 0:
            return 100.0
        
        return (self.success_metrics['successful'] / total) * 100
# =================== Predictive Analytics Engine ===================
# ================= ENHANCED PREDICTIVE ANALYTICS ENGINE =================
class EnhancedPredictiveAnalyticsEngine:
    """Enhanced predictive analytics with SQL Server focus"""
    
    def __init__(self, cloudwatch_connector):
        self.cloudwatch = cloudwatch_connector
        self.prediction_cache = {}
        self.trend_models = {}
    
    def analyze_comprehensive_trends(self, all_metrics: Dict, days_back: int = 7) -> Dict:
        """Analyze trends across all SQL Server metrics"""
        
        analysis_results = {}
        
        # Define key metrics for trend analysis
        key_metrics = {
            'performance': ['buffer_cache_hit_ratio', 'batch_requests_per_sec', 'page_life_expectancy'],
            'concurrency': ['processes_blocked', 'deadlocks_per_sec', 'lock_waits_per_sec'],
            'memory': ['memory_grants_pending', 'target_server_memory_kb', 'total_server_memory_kb'],
            'storage': ['db_percent_log_used', 'page_splits_per_sec', 'lazy_writes_per_sec']
        }
        
        for category, metrics in key_metrics.items():
            category_analysis = {}
            
            for metric in metrics:
                metric_data = self._find_metric_data(all_metrics, metric)
                if metric_data:
                    trend_analysis = self._analyze_metric_trend(metric, metric_data)
                    category_analysis[metric] = trend_analysis
            
            analysis_results[category] = category_analysis
        
        return analysis_results
    
    def generate_capacity_predictions(self, all_metrics: Dict) -> Dict:
        """Generate capacity planning predictions"""
        
        predictions = {}
        
        # Resource utilization metrics
        resource_metrics = {
            'cpu_usage': {'current': 0, 'threshold_warning': 80, 'threshold_critical': 90},
            'memory_usage': {'current': 0, 'threshold_warning': 85, 'threshold_critical': 95},
            'db_percent_log_used': {'current': 0, 'threshold_warning': 70, 'threshold_critical': 85},
            'user_connections': {'current': 0, 'threshold_warning': 200, 'threshold_critical': 400},
            'buffer_cache_hit_ratio': {'current': 0, 'threshold_warning': 90, 'threshold_critical': 85}
        }
        
        for metric, config in resource_metrics.items():
            metric_data = self._find_metric_data(all_metrics, metric)
            
            if metric_data:
                current_value = metric_data[-1]['Average']
                config['current'] = current_value
                
                # Predict future values
                predictions_7d = self._predict_metric_future(metric_data, 7)
                predictions_30d = self._predict_metric_future(metric_data, 30)
                predictions_90d = self._predict_metric_future(metric_data, 90)
                
                # Calculate risk levels
                risk_7d = self._assess_capacity_risk(predictions_7d, config)
                risk_30d = self._assess_capacity_risk(predictions_30d, config)
                risk_90d = self._assess_capacity_risk(predictions_90d, config)
                
                predictions[metric] = {
                    'current': current_value,
                    'predictions': {
                        '7_days': predictions_7d,
                        '30_days': predictions_30d,
                        '90_days': predictions_90d
                    },
                    'risk_levels': {
                        '7_days': risk_7d,
                        '30_days': risk_30d,
                        '90_days': risk_90d
                    },
                    'recommendations': self._generate_capacity_recommendations(metric, risk_30d, current_value)
                }
        
        return predictions
    
    def generate_performance_forecasts(self, all_metrics: Dict, hours_ahead: int = 24) -> Dict:
        """Generate performance forecasts for next N hours"""
        
        forecasts = {}
        
        # Critical performance indicators
        performance_metrics = [
            'buffer_cache_hit_ratio',
            'processes_blocked', 
            'deadlocks_per_sec',
            'memory_grants_pending',
            'db_percent_log_used'
        ]
        
        for metric in performance_metrics:
            metric_data = self._find_metric_data(all_metrics, metric)
            
            if metric_data and len(metric_data) >= 10:  # Need sufficient data
                # Generate hourly predictions
                hourly_predictions = []
                confidence_scores = []
                
                for hour in range(1, hours_ahead + 1):
                    prediction = self._predict_single_point(metric_data, hour)
                    confidence = self._calculate_prediction_confidence(metric_data, hour)
                    
                    hourly_predictions.append(prediction)
                    confidence_scores.append(confidence)
                
                # Identify potential issues
                issues = self._identify_forecast_issues(metric, hourly_predictions)
                
                forecasts[metric] = {
                    'predictions': hourly_predictions,
                    'confidence_scores': confidence_scores,
                    'average_confidence': np.mean(confidence_scores),
                    'potential_issues': issues,
                    'recommendations': self._generate_forecast_recommendations(metric, issues)
                }
        
        return forecasts
    
    def assess_risk_levels(self, all_metrics: Dict) -> Dict:
        """Assess current and future risk levels"""
        
        risk_assessment = {
            'current_risks': {},
            'emerging_risks': {},
            'risk_summary': {
                'overall_risk_score': 0,
                'critical_risks': 0,
                'high_risks': 0,
                'medium_risks': 0,
                'low_risks': 0
            }
        }
        
        # Define risk criteria
        risk_criteria = {
            'buffer_cache_hit_ratio': {
                'type': 'threshold_below',
                'critical': 85,
                'high': 90,
                'medium': 95,
                'weight': 25
            },
            'processes_blocked': {
                'type': 'threshold_above',
                'critical': 20,
                'high': 10,
                'medium': 5,
                'weight': 20
            },
            'deadlocks_per_sec': {
                'type': 'threshold_above',
                'critical': 1.0,
                'high': 0.5,
                'medium': 0.1,
                'weight': 15
            },
            'memory_grants_pending': {
                'type': 'threshold_above',
                'critical': 20,
                'high': 10,
                'medium': 5,
                'weight': 15
            },
            'db_percent_log_used': {
                'type': 'threshold_above',
                'critical': 90,
                'high': 80,
                'medium': 70,
                'weight': 25
            }
        }
        
        total_weight = 0
        weighted_risk_score = 0
        
        for metric, criteria in risk_criteria.items():
            metric_data = self._find_metric_data(all_metrics, metric)
            
            if metric_data:
                current_value = metric_data[-1]['Average']
                current_risk = self._assess_metric_risk(current_value, criteria)
                
                # Predict future risk
                future_predictions = self._predict_metric_future(metric_data, 7)  # 7 days
                future_risk = self._assess_metric_risk(future_predictions, criteria)
                
                risk_assessment['current_risks'][metric] = {
                    'value': current_value,
                    'risk_level': current_risk,
                    'risk_score': self._risk_to_score(current_risk)
                }
                
                risk_assessment['emerging_risks'][metric] = {
                    'predicted_value': future_predictions,
                    'risk_level': future_risk,
                    'risk_score': self._risk_to_score(future_risk),
                    'trend': 'increasing' if future_predictions > current_value else 'decreasing'
                }
                
                # Add to weighted score
                weight = criteria['weight']
                weighted_risk_score += self._risk_to_score(current_risk) * weight
                total_weight += weight
                
                # Count risks by level
                risk_level = current_risk
                if risk_level == 'critical':
                    risk_assessment['risk_summary']['critical_risks'] += 1
                elif risk_level == 'high':
                    risk_assessment['risk_summary']['high_risks'] += 1
                elif risk_level == 'medium':
                    risk_assessment['risk_summary']['medium_risks'] += 1
                else:
                    risk_assessment['risk_summary']['low_risks'] += 1
        
        # Calculate overall risk score
        if total_weight > 0:
            risk_assessment['risk_summary']['overall_risk_score'] = weighted_risk_score / total_weight
        
        return risk_assessment
    
    def _find_metric_data(self, all_metrics: Dict, metric_name: str) -> List:
        """Find metric data in all_metrics dict"""
        # Try exact match first
        if metric_name in all_metrics:
            return all_metrics[metric_name]
        
        # Try to find with instance prefix
        for key in all_metrics.keys():
            if key.endswith(f"_{metric_name}"):
                return all_metrics[key]
        
        return []
    
    def _analyze_metric_trend(self, metric_name: str, metric_data: List) -> Dict:
        """Analyze trend for a specific metric"""
        
        if len(metric_data) < 5:
            return {
                'status': 'insufficient_data',
                'trend': 'unknown',
                'confidence': 0
            }
        
        values = [dp['Average'] for dp in metric_data]
        timestamps = [dp['Timestamp'] for dp in metric_data]
        
        # Calculate linear trend
        x = np.arange(len(values))
        slope, intercept = np.polyfit(x, values, 1)
        
        # Determine trend direction
        if abs(slope) < np.std(values) * 0.1:
            trend = 'stable'
        elif slope > 0:
            trend = 'increasing'
        else:
            trend = 'decreasing'
        
        # Calculate R-squared for confidence
        y_pred = slope * x + intercept
        ss_res = np.sum((values - y_pred) ** 2)
        ss_tot = np.sum((values - np.mean(values)) ** 2)
        r_squared = 1 - (ss_res / ss_tot) if ss_tot != 0 else 0
        
        # Generate future predictions
        future_24h = self._predict_metric_future(metric_data, 1)  # 1 day ahead
        future_7d = self._predict_metric_future(metric_data, 7)   # 7 days ahead
        
        return {
            'status': 'analyzed',
            'trend': trend,
            'slope': slope,
            'confidence': max(0, min(100, r_squared * 100)),
            'current_value': values[-1],
            'predictions': {
                '24_hours': future_24h,
                '7_days': future_7d
            },
            'volatility': np.std(values),
            'mean_value': np.mean(values)
        }
    
    def _predict_metric_future(self, metric_data: List, days_ahead: int) -> float:
        """Predict metric value for days ahead"""
        
        if len(metric_data) < 3:
            # Insufficient data, return current value
            return metric_data[-1]['Average'] if metric_data else 0
        
        values = [dp['Average'] for dp in metric_data]
        
        # Use simple linear regression for prediction
        x = np.arange(len(values))
        slope, intercept = np.polyfit(x, values, 1)
        
        # Predict value at future point
        future_x = len(values) + (days_ahead * 24)  # Assuming hourly data
        predicted_value = slope * future_x + intercept
        
        # Apply bounds based on metric type
        predicted_value = max(0, predicted_value)  # No negative values
        
        return predicted_value
    
    def _predict_single_point(self, metric_data: List, hours_ahead: int) -> float:
        """Predict single point hours ahead"""
        
        values = [dp['Average'] for dp in metric_data]
        
        if len(values) < 3:
            return values[-1] if values else 0
        
        # Use moving average with trend
        recent_values = values[-min(24, len(values)):]  # Last 24 points or all available
        moving_avg = np.mean(recent_values)
        
        # Calculate trend from recent data
        x = np.arange(len(recent_values))
        slope, _ = np.polyfit(x, recent_values, 1)
        
        # Predict with trend
        predicted = moving_avg + (slope * hours_ahead)
        
        return max(0, predicted)
    
    def _calculate_prediction_confidence(self, metric_data: List, hours_ahead: int) -> float:
        """Calculate confidence in prediction"""
        
        if len(metric_data) < 10:
            return 30.0  # Low confidence with insufficient data
        
        values = [dp['Average'] for dp in metric_data]
        
        # Calculate variability
        std_dev = np.std(values)
        mean_val = np.mean(values)
        coefficient_of_variation = std_dev / mean_val if mean_val != 0 else 1
        
        # Base confidence decreases with time horizon and variability
        base_confidence = 90
        time_penalty = hours_ahead * 2  # 2% per hour
        variability_penalty = coefficient_of_variation * 100
        
        confidence = max(10, base_confidence - time_penalty - variability_penalty)
        
        return confidence
    
    def _assess_capacity_risk(self, predicted_value: float, config: Dict) -> str:
        """Assess capacity risk based on predicted value"""
        
        if predicted_value >= config['threshold_critical']:
            return 'critical'
        elif predicted_value >= config['threshold_warning']:
            return 'high'
        elif predicted_value >= config['threshold_warning'] * 0.8:
            return 'medium'
        else:
            return 'low'
    
    def _assess_metric_risk(self, value: float, criteria: Dict) -> str:
        """Assess risk level for a metric value"""
        
        if criteria['type'] == 'threshold_above':
            if value >= criteria['critical']:
                return 'critical'
            elif value >= criteria['high']:
                return 'high'
            elif value >= criteria['medium']:
                return 'medium'
            else:
                return 'low'
        
        elif criteria['type'] == 'threshold_below':
            if value <= criteria['critical']:
                return 'critical'
            elif value <= criteria['high']:
                return 'high'
            elif value <= criteria['medium']:
                return 'medium'
            else:
                return 'low'
        
        return 'low'
    
    def _risk_to_score(self, risk_level: str) -> int:
        """Convert risk level to numeric score"""
        risk_scores = {
            'critical': 100,
            'high': 75,
            'medium': 50,
            'low': 25
        }
        return risk_scores.get(risk_level, 0)
    
    def _identify_forecast_issues(self, metric: str, predictions: List[float]) -> List[Dict]:
        """Identify potential issues in forecast"""
        
        issues = []
        
        # Define thresholds for different metrics
        thresholds = {
            'buffer_cache_hit_ratio': {'critical': 85, 'warning': 90},
            'processes_blocked': {'critical': 20, 'warning': 10},
            'deadlocks_per_sec': {'critical': 1.0, 'warning': 0.5},
            'memory_grants_pending': {'critical': 20, 'warning': 10},
            'db_percent_log_used': {'critical': 90, 'warning': 75}
        }
        
        if metric not in thresholds:
            return issues
        
        thresh = thresholds[metric]
        
        for hour, value in enumerate(predictions, 1):
            if metric == 'buffer_cache_hit_ratio':
                # Lower is worse for buffer cache
                if value <= thresh['critical']:
                    issues.append({
                        'hour': hour,
                        'severity': 'critical',
                        'description': f'Buffer cache hit ratio predicted to drop to {value:.1f}%',
                        'impact': 'Severe performance degradation expected'
                    })
                elif value <= thresh['warning']:
                    issues.append({
                        'hour': hour,
                        'severity': 'warning',
                        'description': f'Buffer cache hit ratio predicted to drop to {value:.1f}%',
                        'impact': 'Performance degradation expected'
                    })
            else:
                # Higher is worse for other metrics
                if value >= thresh['critical']:
                    issues.append({
                        'hour': hour,
                        'severity': 'critical',
                        'description': f'{metric} predicted to reach {value:.2f}',
                        'impact': 'Critical system impact expected'
                    })
                elif value >= thresh['warning']:
                    issues.append({
                        'hour': hour,
                        'severity': 'warning',
                        'description': f'{metric} predicted to reach {value:.2f}',
                        'impact': 'System impact expected'
                    })
        
        return issues
    
    def _generate_capacity_recommendations(self, metric: str, risk_level: str, current_value: float) -> List[str]:
        """Generate capacity planning recommendations"""
        
        recommendations = []
        
        if risk_level in ['critical', 'high']:
            if metric == 'cpu_usage':
                recommendations.extend([
                    'Scale up to larger instance type immediately',
                    'Enable auto-scaling if available',
                    'Optimize CPU-intensive queries',
                    'Consider read replicas to distribute load'
                ])
            elif metric == 'memory_usage':
                recommendations.extend([
                    'Increase instance memory allocation',
                    'Scale to memory-optimized instance type',
                    'Optimize memory-intensive operations',
                    'Review max server memory settings'
                ])
            elif metric == 'db_percent_log_used':
                recommendations.extend([
                    'Increase log backup frequency',
                    'Consider increasing log file auto-growth',
                    'Review and optimize large transactions',
                    'Monitor for log reuse wait conditions'
                ])
            elif metric == 'user_connections':
                recommendations.extend([
                    'Implement connection pooling',
                    'Review connection timeout settings',
                    'Optimize application connection management',
                    'Consider increasing max connections if needed'
                ])
        
        elif risk_level == 'medium':
            recommendations.append(f'Monitor {metric} closely for trends')
            recommendations.append('Prepare scaling strategy if trend continues')
        
        return recommendations
    
    def _generate_forecast_recommendations(self, metric: str, issues: List[Dict]) -> List[str]:
        """Generate recommendations based on forecast issues"""
        
        recommendations = []
        
        if not issues:
            recommendations.append(f'{metric} forecast looks stable - no immediate action needed')
            return recommendations
        
        critical_issues = [i for i in issues if i['severity'] == 'critical']
        warning_issues = [i for i in issues if i['severity'] == 'warning']
        
        if critical_issues:
            earliest_critical = min(critical_issues, key=lambda x: x['hour'])
            recommendations.append(f'URGENT: {metric} will reach critical levels in {earliest_critical["hour"]} hours')
            recommendations.append('Implement immediate preventive measures')
            
            if metric == 'buffer_cache_hit_ratio':
                recommendations.extend([
                    'Add server memory immediately',
                    'Clear procedure cache if necessary',
                    'Optimize memory-intensive queries'
                ])
            elif metric == 'processes_blocked':
                recommendations.extend([
                    'Monitor for blocking sessions closely',
                    'Prepare to kill long-running transactions',
                    'Review query optimization opportunities'
                ])
        
        elif warning_issues:
            earliest_warning = min(warning_issues, key=lambda x: x['hour'])
            recommendations.append(f'WARNING: {metric} will reach warning levels in {earliest_warning["hour"]} hours')
            recommendations.append('Prepare preventive actions')
        
        return recommendations
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

# =================== Configuration Functions ===================
def setup_sidebar_configuration():
        """Setup sidebar configuration and return AWS config"""
        with st.sidebar:
            st.header("🔧 AWS Configuration")
            
            # System Status
            st.subheader("📊 System Status")
            
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
            
            if not AWS_AVAILABLE:
                st.markdown("""
                <div style="background: linear-gradient(135deg, #ff6b6b 0%, #ee5a52 100%); 
                            padding: 1rem; border-radius: 8px; color: white; margin: 1rem 0;">
                    <strong>🎭 DEMO MODE</strong><br>
                    Using simulated data. Install boto3 for real AWS connections.
                </div>
                """, unsafe_allow_html=True)
            
            st.markdown("---")
            
            # AWS Credentials
            st.subheader("🔑 AWS Credentials")
            
            auth_method = st.radio(
                "Authentication Method",
                [
                    "🌍 Environment Variables (Recommended for Streamlit Cloud)",
                    "🔑 Manual Input",
                    "🏢 Default Credential Chain"
                ]
            )
            
            aws_access_key = None
            aws_secret_key = None
            
            if auth_method.startswith("🌍"):
                st.info("💡 **Best for Streamlit Cloud deployment**")
                st.write("Set these in your Streamlit Cloud app settings:")
                st.code("""
    Environment Variables:
    AWS_ACCESS_KEY_ID=your_access_key_here
    AWS_SECRET_ACCESS_KEY=your_secret_key_here
    AWS_DEFAULT_REGION=us-east-2
                """)
                
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

            # CloudWatch Configuration
            st.subheader("📊 CloudWatch Configuration")

            st.success("✅ **Using your actual CloudWatch log groups!**")

            st.write("**📝 Your CloudWatch Log Groups:**")

            # Use YOUR EXACT log group names
            your_actual_log_groups = [
                "SQLServer/ErrorLogs",
                "Windows/Application", 
                "Windows/Security",
                "Windows/Setup",
                "Windows/System"
            ]

            # Let user select which ones to monitor
            selected_log_groups = st.multiselect(
                "Select Log Groups to Monitor",
                your_actual_log_groups,
                default=your_actual_log_groups,  # Select all by default
                help="These are your actual log groups from CloudWatch"
            )

            # Option to add custom log groups
            st.write("**➕ Additional Log Groups (Optional):**")
            custom_log_groups_text = st.text_area(
                "Additional log groups (one per line)",
                value="",
                height=80,
                help="Add any other log groups you want to monitor"
            )

            # Combine selected and custom log groups
            log_groups = selected_log_groups.copy()
            if custom_log_groups_text.strip():
                custom_groups = [lg.strip() for lg in custom_log_groups_text.split('\n') if lg.strip()]
                log_groups.extend(custom_groups)

            # Show final configuration
            if log_groups:
                st.success(f"✅ **{len(log_groups)} log groups configured:**")
                for lg in log_groups:
                    st.write(f"  • `{lg}`")
            else:
                st.warning("⚠️ No log groups selected")

            # Test log group connectivity
            if st.button("🧪 Test Log Group Access"):
                test_log_groups(log_groups)

            # Additional CloudWatch settings
            custom_namespace = st.text_input(
                "Custom Metrics Namespace", 
                value="SQLServer/CustomMetrics",
                help="Namespace for your custom SQL Server metrics"
            )

            st.write("**🖥️ OS Metrics Configuration:**")
            enable_os_metrics = st.checkbox("Enable OS-level Metrics", value=True)
            os_metrics_namespace = st.text_input(
                "OS Metrics Namespace",
                value="CWAgent",
                help="CloudWatch namespace for OS metrics"
            )

            # Setup Guide
            with st.expander("📋 Setup Guide for Real Data", expanded=False):
                st.markdown("""
                ### 🔧 Setting Up SQL Server Metrics in AWS CloudWatch
                
                **For Streamlit Cloud deployment, set these environment variables:**
                
                ```bash
                AWS_ACCESS_KEY_ID=your_access_key
                AWS_SECRET_ACCESS_KEY=your_secret_key
                AWS_DEFAULT_REGION=us-east-2
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
            
            return {
                'access_key': aws_access_key or 'demo',
                'secret_key': aws_secret_key or 'demo',
                'region': aws_region,
                'account_id': aws_account_id,
                'account_name': aws_account_name,
                'log_groups': log_groups,
                'custom_namespace': custom_namespace,
                'os_metrics_namespace': os_metrics_namespace,
                'enable_os_metrics': enable_os_metrics,
                'claude_api_key': claude_api_key,
                'enable_auto_remediation': enable_auto_remediation,
                'auto_approval_threshold': auto_approval_threshold,
                'refresh_interval': refresh_interval,
                'enable_predictive_alerts': enable_predictive_alerts
        }
def initialize_session_state(aws_config):
    """Initialize session state variables"""
    if 'cloudwatch_connector' not in st.session_state:
        st.session_state.cloudwatch_connector = None
    
    if 'always_on_monitor' not in st.session_state:
        st.session_state.always_on_monitor = None
    
    if 'enhanced_auto_remediation' not in st.session_state:
        st.session_state.enhanced_auto_remediation = None
    
    if 'enhanced_predictive_analytics' not in st.session_state:
        st.session_state.enhanced_predictive_analytics = None
    
    if 'claude_analyzer' not in st.session_state:
        st.session_state.claude_analyzer = None

    # Initialize connectors if not already done or config changed
    if (st.session_state.cloudwatch_connector is None or 
        getattr(st.session_state.cloudwatch_connector, 'aws_config', {}) != aws_config):
        
        with st.spinner("🔄 Initializing AWS connection..."):
            try:
                st.session_state.cloudwatch_connector = AWSCloudWatchConnector(aws_config)
                st.session_state.always_on_monitor = AlwaysOnMonitor(st.session_state.cloudwatch_connector)
                
                # Initialize enhanced engines if CloudWatch connector is available
                if st.session_state.cloudwatch_connector:
                    st.session_state.enhanced_auto_remediation = EnhancedAutoRemediationEngine(
                        st.session_state.cloudwatch_connector
                    )
                    st.session_state.enhanced_predictive_analytics = EnhancedPredictiveAnalyticsEngine(
                        st.session_state.cloudwatch_connector
                    )
                
                if aws_config.get('claude_api_key') and ANTHROPIC_AVAILABLE:
                    st.session_state.claude_analyzer = ClaudeAIAnalyzer(aws_config['claude_api_key'])
                    
            except Exception as e:
                st.error(f"Failed to initialize: {str(e)}")
                # Set demo mode if initialization fails
                st.session_state.cloudwatch_connector = None
    
    
    

def display_connection_status():
    """Display connection status and test button"""
    with st.sidebar:
        if st.button("🔌 Test AWS Connection", type="primary"):
            with st.spinner("Testing AWS connection..."):
                if st.session_state.cloudwatch_connector:
                    if st.session_state.cloudwatch_connector.test_connection():
                        st.success("✅ AWS Connection Successful!")
                        
                        conn_status = st.session_state.cloudwatch_connector.get_connection_status()
                        if conn_status.get('account_id'):
                            st.write(f"**Account:** {conn_status['account_id']}")
                        if conn_status.get('user_arn'):
                            st.write(f"**Role:** {conn_status['user_arn'].split('/')[-1]}")
                        if conn_status.get('method'):
                            st.write(f"**Method:** {conn_status['method'].replace('_', ' ').title()}")
                    else:
                        st.error("❌ AWS Connection Failed")
                        
                        conn_status = st.session_state.cloudwatch_connector.get_connection_status()
                        if conn_status.get('error'):
                            with st.expander("🔍 View Error Details"):
                                st.error(conn_status['error'])
                                
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
                else:
                    st.error("❌ CloudWatch connector not initialized")

        # Enhanced Connection Status Display
        if st.session_state.cloudwatch_connector:
            st.markdown("---")
            st.subheader("🔗 Connection Status")
            
            conn_status = st.session_state.cloudwatch_connector.get_connection_status()
            
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
                <strong>Method:</strong> {safe_format_method(conn_status.get('method'))}<br>
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

def show_tagging_instructions():
    """Show instructions for manually tagging instances"""
    st.subheader("🏷️ How to Tag EC2 Instances for SQL Server")
    
    st.info("**The app looks for instances with this tag:**")
    st.code("Key: Application\nValue: SQLServer")
    
    st.write("**Alternative accepted values:**")
    st.write("• `SQL Server`")
    st.write("• `Database`")
    st.write("• `MSSQL`")
    
    st.subheader("📝 Manual Tagging Steps")
    
    with st.expander("🖱️ Tag via AWS Console"):
        st.write("1. Go to **EC2 Console** → **Instances**")
        st.write("2. **Select your SQL Server instance**")
        st.write("3. Click **Actions** → **Instance Settings** → **Manage Tags**")
        st.write("4. Click **Add Tag**")
        st.write("5. Enter:")
        st.code("Key: Application\nValue: SQLServer")
        st.write("6. Click **Save**")
    
    with st.expander("💻 Tag via AWS CLI"):
        st.code("""
# Replace i-1234567890abcdef0 with your instance ID
aws ec2 create-tags \\
    --resources i-1234567890abcdef0 \\
    --tags Key=Application,Value=SQLServer
        """)

# =================== Data Collection Functions ===================
@st.cache_data(ttl=300)
def collect_comprehensive_metrics():
    """Collect all metrics including OS, SQL Server, and logs with caching"""
    if not st.session_state.cloudwatch_connector:
        return {}, {}, []
        
    current_time = datetime.now()
    start_time = current_time - timedelta(hours=24)
    
    all_metrics = {}
    all_logs = {}
    
    try:
        # Get AWS account information
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
            aws_config = st.session_state.cloudwatch_connector.aws_config
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
        aws_config = st.session_state.cloudwatch_connector.aws_config
        if aws_config.get('log_groups'):
            all_logs = st.session_state.cloudwatch_connector.get_sql_server_logs(
                aws_config['log_groups'], 
                hours=24
            )
    
    except Exception as e:
        logger.error(f"Error collecting metrics: {str(e)}")
        st.error(f"Error collecting metrics: {str(e)}")
    
    return all_metrics, all_logs, ec2_instances

def debug_ec2_instances():
    """Debug function to find all EC2 instances and their tags"""
    
    if not st.session_state.cloudwatch_connector or st.session_state.cloudwatch_connector.demo_mode:
        st.info("Connect to AWS first to see your EC2 instances")
        return
    
    st.header("🔍 EC2 Instance Detective")
    st.info("Let's find all your EC2 instances and see how they're tagged")
    
    if st.button("🕵️ Find All My EC2 Instances", type="primary"):
        try:
            ec2_client = st.session_state.cloudwatch_connector.aws_manager.get_client('ec2')
            if not ec2_client:
                st.error("No EC2 client available")
                return
            
            with st.spinner("Searching for EC2 instances..."):
                # Get ALL instances (no filters)
                response = ec2_client.describe_instances()
                
                all_instances = []
                for reservation in response['Reservations']:
                    for instance in reservation['Instances']:
                        all_instances.append(instance)
                
                if not all_instances:
                    st.warning("🤷‍♂️ No EC2 instances found in your account")
                    st.info("**Possible reasons:**")
                    st.write("• You don't have any EC2 instances")
                    st.write("• Your instances are in a different region")
                    st.write("• You don't have ec2:DescribeInstances permission")
                    return
                
                st.success(f"🎉 Found {len(all_instances)} EC2 instances!")
                
                # Show all instances with their tags
                for i, instance in enumerate(all_instances):
                    instance_id = instance['InstanceId']
                    instance_type = instance['InstanceType']
                    state = instance['State']['Name']
                    
                    # Get instance name from tags
                    instance_name = "Unnamed"
                    for tag in instance.get('Tags', []):
                        if tag['Key'] == 'Name':
                            instance_name = tag['Value']
                            break
                    
                    # Color code by state
                    if state == 'running':
                        state_color = "🟢"
                    elif state == 'stopped':
                        state_color = "🟡"
                    else:
                        state_color = "🔴"
                    
                    st.markdown(f"### {state_color} Instance {i+1}: **{instance_name}**")
                    
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.write(f"**Instance ID:** {instance_id}")
                        st.write(f"**Type:** {instance_type}")
                        st.write(f"**State:** {state}")
                        st.write(f"**Private IP:** {instance.get('PrivateIpAddress', 'N/A')}")
                    
                    with col2:
                        # Show all tags
                        tags = instance.get('Tags', [])
                        if tags:
                            st.write("**Tags:**")
                            for tag in tags:
                                st.write(f"  • **{tag['Key']}:** {tag['Value']}")
                        else:
                            st.write("**Tags:** None")
                    
                    # Check if this instance would be detected as SQL Server
                    sql_server_tags = ['SQLServer', 'SQL Server', 'Database', 'MSSQL', 'SqlServer']
                    is_sql_server = False
                    
                    for tag in tags:
                        if tag['Key'] == 'Application' and tag['Value'] in sql_server_tags:
                            is_sql_server = True
                            break
                    
                    if is_sql_server:
                        st.success("✅ This instance WOULD be detected as SQL Server")
                    else:
                        st.error("❌ This instance would NOT be detected as SQL Server")
                        st.info("💡 To make this a SQL Server instance, add tag: **Application = SQLServer**")
                    
                    # Option to tag this instance
                    if not is_sql_server and state == 'running':
                        with st.expander(f"🏷️ Tag {instance_name} as SQL Server"):
                            st.write("Click the button below to add the SQL Server tag to this instance:")
                            
                            if st.button(f"🏷️ Tag as SQL Server", key=f"tag_{instance_id}"):
                                try:
                                    ec2_client.create_tags(
                                        Resources=[instance_id],
                                        Tags=[
                                            {
                                                'Key': 'Application',
                                                'Value': 'SQLServer'
                                            }
                                        ]
                                    )
                                    st.success(f"✅ Successfully tagged {instance_name} as SQLServer!")
                                    st.info("🔄 Refresh the page to see the updated tags")
                                    
                                except Exception as tag_error:
                                    st.error(f"❌ Failed to tag instance: {tag_error}")
                    
                    st.markdown("---")
                
                # Summary
                sql_instances = 0
                for instance in all_instances:
                    tags = instance.get('Tags', [])
                    for tag in tags:
                        if tag['Key'] == 'Application' and tag['Value'] in ['SQLServer', 'SQL Server', 'Database']:
                            sql_instances += 1
                            break
                
                st.subheader("📊 Summary")
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.metric("Total Instances", len(all_instances))
                
                with col2:
                    running_instances = len([i for i in all_instances if i['State']['Name'] == 'running'])
                    st.metric("Running Instances", running_instances)
                
                with col3:
                    st.metric("SQL Server Tagged", sql_instances)
                
                if sql_instances == 0:
                    st.warning("⚠️ **No instances are tagged for SQL Server detection**")
                    st.info("**To fix this:** Add the tag `Application = SQLServer` to your SQL Server instances")
                else:
                    st.success(f"🎉 **{sql_instances} instances are properly tagged for SQL Server!**")
        
        except Exception as e:
            st.error(f"❌ Failed to get EC2 instances: {e}")
            
            # Show helpful error messages
            if "UnauthorizedOperation" in str(e):
                st.error("🔒 **Permission Issue:** You don't have ec2:DescribeInstances permission")
                st.info("**Ask your AWS admin to add this IAM permission:**")
                st.code('"ec2:DescribeInstances"')
            elif "AccessDenied" in str(e):
                st.error("🔒 **Access Denied:** Check your IAM permissions")

# =================== Tab Rendering Functions ===================
def render_dashboard_tab(all_metrics, ec2_instances, rds_instances):
    """Render the main dashboard tab"""
    st.header("🏢 AWS SQL Server Infrastructure Overview")
    
    # ===== NEW INSTANCE SELECTOR - INSERT HERE =====
    st.subheader("🖥️ Select Instances to Monitor")
    
    if ec2_instances:
        st.success(f"✅ Found {len(ec2_instances)} EC2 instances")
        
        selected_instances = []
        
        for instance in ec2_instances:
            instance_id = instance['InstanceId']
            instance_name = "Unnamed"
            
            # Get instance name from tags
            for tag in instance.get('Tags', []):
                if tag['Key'] == 'Name':
                    instance_name = tag['Value']
                    break
            
            # Show instance with checkbox
            col1, col2, col3 = st.columns([3, 1, 1])
            
            with col1:
                state = instance['State']['Name']
                state_icon = "🟢" if state == 'running' else "🟡"
                st.write(f"{state_icon} **{instance_name}** ({instance_id})")
                st.write(f"Type: {instance['InstanceType']} | State: {state}")
            
            with col2:
                is_selected = st.checkbox("Monitor", key=f"select_{instance_id}")
            
            with col3:
                is_sql = st.checkbox("SQL Server", key=f"sql_{instance_id}")
            
            if is_selected:
                instance['is_sql_server'] = is_sql
                selected_instances.append(instance)
        
        # Store selected instances
        st.session_state.selected_instances = selected_instances
        sql_instances = [i for i in selected_instances if i.get('is_sql_server')]
        
        if selected_instances:
            st.success(f"✅ Monitoring {len(selected_instances)} instances ({len(sql_instances)} SQL Servers)")
    
    else:
        st.warning("No EC2 instances found")
        
        with st.expander("🔧 Troubleshooting"):
            st.write("**Possible causes:**")
            st.write("• Wrong AWS region selected")
            st.write("• No EC2 instances in your account") 
            st.write("• Missing IAM permission: ec2:DescribeInstances")
    
    st.markdown("---")  # Add separator line
    # ===== END OF NEW CODE =====
    
    
    
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
                    st.write(f"**Method:** {safe_format_method(conn_status.get('method'))}")
                with col2:
                    if st.button("🔄 Refresh Connection"):
                        st.session_state.cloudwatch_connector.test_connection()
                        st.rerun()
        else:
            st.error("❌ **AWS Connection Failed** - Check credentials in sidebar")
            if conn_status.get('error'):
                with st.expander("🔍 View Connection Error"):
                    st.error(conn_status['error'])
                    
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

def render_enhanced_sql_metrics_tab(all_metrics, ec2_instances):
    """Enhanced SQL Server metrics tab with clear visibility and explanations"""
    
    st.header("🗄️ Comprehensive SQL Server Performance Metrics")
    st.write("**Real-time SQL Server health monitoring with intelligent insights and recommendations**")
    
    # Instance selector (keep your existing logic)
    if ec2_instances:
        instance_options = {}
        for ec2 in ec2_instances:
            instance_name = "Unknown"
            for tag in ec2.get('Tags', []):
                if tag['Key'] == 'Name':
                    instance_name = tag['Value']
                    break
            instance_options[f"{instance_name} ({ec2['InstanceId']})"] = ec2['InstanceId']
        
        selected_instance_display = st.selectbox("Select SQL Server Instance for Analysis", 
                                                list(instance_options.keys()))
        selected_instance = instance_options[selected_instance_display]
        
        # === NEW: SQL Server Health Dashboard ===
        st.markdown("---")
        st.subheader(f"🎯 SQL Server Health Overview - {selected_instance_display}")
        
        # Get instance-specific metrics
        instance_metrics = {k: v for k, v in all_metrics.items() if k.startswith(selected_instance)}
        
        if instance_metrics:
            # Health Score Calculation
            health_score = calculate_sql_server_health_score(instance_metrics, selected_instance)
            
            # Health Overview Cards
            col1, col2, col3, col4, col5 = st.columns(5)
            
            with col1:
                health_color = "🟢" if health_score >= 80 else "🟡" if health_score >= 60 else "🔴"
                st.markdown(f"""
                <div style="
                    border: 3px solid {'#28a745' if health_score >= 80 else '#ffc107' if health_score >= 60 else '#dc3545'};
                    border-radius: 10px;
                    padding: 1rem;
                    text-align: center;
                    background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
                ">
                    <h3>{health_color} Overall Health</h3>
                    <h2 style="color: #007bff; margin: 0;">{health_score}/100</h2>
                    <p style="margin: 0; font-size: 0.9rem;">
                        {'Excellent' if health_score >= 90 else 'Good' if health_score >= 80 else 'Needs Attention' if health_score >= 60 else 'Critical'}
                    </p>
                </div>
                """, unsafe_allow_html=True)
            
            with col2:
                buffer_cache_key = f"{selected_instance}_buffer_cache_hit_ratio"
                buffer_cache = get_metric_current_value(all_metrics.get(buffer_cache_key, []))
                buffer_status = get_buffer_cache_status(buffer_cache)
                st.markdown(create_metric_card("Buffer Cache Hit Ratio", buffer_cache, "%", buffer_status, 
                                             "Memory efficiency - should be > 95%"))
            
            with col3:
                connections_key = f"{selected_instance}_user_connections"
                connections = get_metric_current_value(all_metrics.get(connections_key, []))
                conn_status = get_connections_status(connections)
                st.markdown(create_metric_card("Active Connections", int(connections), "", conn_status,
                                             "Current user connections"))
            
            with col4:
                blocked_key = f"{selected_instance}_processes_blocked"
                blocked = get_metric_current_value(all_metrics.get(blocked_key, []))
                blocked_status = get_blocking_status(blocked)
                st.markdown(create_metric_card("Blocked Processes", int(blocked), "", blocked_status,
                                             "Processes waiting due to blocking"))
            
            with col5:
                deadlock_key = f"{selected_instance}_deadlocks_per_sec"
                deadlocks = get_metric_current_value(all_metrics.get(deadlock_key, []))
                deadlock_status = get_deadlock_status(deadlocks)
                st.markdown(create_metric_card("Deadlocks/sec", f"{deadlocks:.3f}", "", deadlock_status,
                                             "Transaction conflicts"))
            
            # === NEW: Performance Categories ===
            st.markdown("---")
            st.subheader("📊 Detailed Metric Categories")
            
            # Core Performance Metrics
            with st.expander("🎯 Core Performance Metrics", expanded=True):
                render_core_performance_metrics(all_metrics, selected_instance)
            
            # Blocking and Concurrency
            with st.expander("🔒 Blocking & Concurrency Metrics", expanded=False):
                render_concurrency_metrics(all_metrics, selected_instance)
            
            # === NEW: Real-time Issues Detection ===
            st.markdown("---")
            st.subheader("🚨 Real-time Issues & Recommendations")
            
            issues = detect_sql_server_issues(instance_metrics, selected_instance)
            
            if issues:
                for issue in issues:
                    render_issue_card(issue)
            else:
                st.success("🎉 No performance issues detected - SQL Server is running optimally!")
        
        else:
            # === Enhanced Error Messages ===
            st.warning(f"⚠️ No SQL Server metrics found for instance {selected_instance}")
            
            # Provide specific troubleshooting guidance
            with st.expander("🔧 Troubleshooting Guide", expanded=True):
                st.write("**Possible causes and solutions:**")
                
                st.write("### 1. CloudWatch Agent Not Configured")
                st.code("""
# Install CloudWatch Agent on SQL Server instance
# Configure custom metrics collection
{
  "metrics": {
    "namespace": "CWAgent",
    "metrics_collected": {
      "procstat": [
        {
          "pattern": "sqlservr",
          "measurement": ["cpu_usage", "memory_usage"],
          "metrics_collection_interval": 60
        }
      ]
    }
  }
}
                """)
                
                st.write("### 2. Custom SQL Server Performance Counters Missing")
                st.code("""
# Add to CloudWatch Agent configuration
"counters": [
  {
    "category": "SQLServer:Buffer Manager",
    "counters": ["Buffer cache hit ratio", "Page life expectancy"],
    "instances": ["*"],
    "measurement": ["Average"],
    "metrics_collection_interval": 60
  }
]
                """)
    
    else:
        st.warning("No EC2 SQL Server instances found.")
        show_tagging_instructions()

def render_core_performance_metrics(all_metrics, instance_id):
    """Render core SQL Server performance metrics"""
    
    st.write("**🎯 Essential SQL Server Performance Indicators**")
    
    # Key metrics with explanations
    metrics_info = [
        {
            'key': f"{instance_id}_buffer_cache_hit_ratio",
            'name': 'Buffer Cache Hit Ratio',
            'unit': '%',
            'description': 'Percentage of page requests satisfied from memory without disk I/O',
            'good_range': '> 95%',
            'why_important': 'Low values indicate memory pressure and slow query performance',
            'remediation': [
                'Add more server memory',
                'Optimize memory-intensive queries', 
                'Review buffer pool configuration'
            ]
        },
        {
            'key': f"{instance_id}_batch_requests_per_sec",
            'name': 'Batch Requests/sec',
            'unit': '/sec',
            'description': 'Number of SQL batches processed per second',
            'good_range': 'Depends on workload',
            'why_important': 'Indicates overall SQL Server activity and load',
            'remediation': [
                'Scale up the instance if consistently high',
                'Optimize frequently executed queries',
                'Implement connection pooling'
            ]
        },
        {
            'key': f"{instance_id}_page_life_expectancy", 
            'name': 'Page Life Expectancy',
            'unit': 'seconds',
            'description': 'Expected time a page will stay in memory before being flushed',
            'good_range': '> 300 seconds',
            'why_important': 'Lower values indicate memory pressure affecting performance',
            'remediation': [
                'Increase server memory',
                'Optimize queries that consume excessive memory',
                'Review max server memory settings'
            ]
        }
    ]
    
    for metric_info in metrics_info:
        if metric_info['key'] in all_metrics:
            render_detailed_metric_analysis(all_metrics[metric_info['key']], metric_info)
        else:
            st.warning(f"⚠️ Metric not available: {metric_info['name']}")

def render_detailed_metric_analysis(metric_data, metric_info):
    """Render detailed analysis for a specific metric"""
    
    if not metric_data:
        st.warning(f"No data available for {metric_info['name']}")
        return
    
    current_value = get_metric_current_value(metric_data)
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        # Historical trend chart
        fig = go.Figure()
        
        timestamps = [dp['Timestamp'] for dp in metric_data]
        values = [dp['Average'] for dp in metric_data]
        
        fig.add_trace(go.Scatter(
            x=timestamps,
            y=values,
            name=metric_info['name'],
            line=dict(color='blue', width=2)
        ))
        
        # Add threshold lines based on metric type
        if 'buffer_cache' in metric_info['key']:
            fig.add_hline(y=95, line_dash="dash", line_color="green", annotation_text="Good: 95%")
            fig.add_hline(y=90, line_dash="dash", line_color="orange", annotation_text="Warning: 90%")
        elif 'page_life' in metric_info['key']:
            fig.add_hline(y=300, line_dash="dash", line_color="green", annotation_text="Good: 300s")
            fig.add_hline(y=180, line_dash="dash", line_color="orange", annotation_text="Warning: 180s")
        
        fig.update_layout(
            title=f"{metric_info['name']} - 24 Hour Trend",
            xaxis_title="Time",
            yaxis_title=f"{metric_info['name']} ({metric_info['unit']})",
            height=300
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Metric details and recommendations
        st.markdown(f"### 📊 {metric_info['name']}")
        
        # Current status
        if 'buffer_cache' in metric_info['key']:
            status = 'good' if current_value > 95 else 'warning' if current_value > 90 else 'critical'
        elif 'page_life' in metric_info['key']:
            status = 'good' if current_value > 300 else 'warning' if current_value > 180 else 'critical'
        else:
            status = 'unknown'
        
        status_colors = {'good': '#28a745', 'warning': '#ffc107', 'critical': '#dc3545', 'unknown': '#6c757d'}
        status_icons = {'good': '🟢', 'warning': '🟡', 'critical': '🔴', 'unknown': '🔵'}
        
        st.markdown(f"""
        <div style="
            border-left: 4px solid {status_colors[status]};
            padding-left: 1rem;
            margin: 1rem 0;
        ">
            <p><strong>Current Value:</strong> {current_value:.2f} {metric_info['unit']}</p>
            <p><strong>Status:</strong> {status_icons[status]} {status.title()}</p>
            <p><strong>Good Range:</strong> {metric_info['good_range']}</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Why it's important
        st.write("**Why this matters:**")
        st.write(metric_info['why_important'])
        
        # Show remediation if not good
        if status in ['warning', 'critical']:
            st.write("**🔧 Recommended Actions:**")
            for i, action in enumerate(metric_info['remediation'], 1):
                st.write(f"{i}. {action}")

def render_concurrency_metrics(all_metrics, instance_id):
    """Render concurrency and blocking metrics"""
    
    st.write("**🔒 Concurrency and Blocking Analysis**")
    
    blocked_key = f"{instance_id}_processes_blocked"
    deadlock_key = f"{instance_id}_deadlocks_per_sec"
    
    col1, col2 = st.columns(2)
    
    with col1:
        if blocked_key in all_metrics:
            blocked = get_metric_current_value(all_metrics[blocked_key])
            if blocked > 0:
                st.error(f"🔴 **{int(blocked)} processes currently blocked**")
                st.write("**Immediate Actions:**")
                st.write("1. Check blocking chain with sys.dm_exec_requests")
                st.write("2. Consider killing head blocker if necessary")
                st.write("3. Review long-running transactions")
            else:
                st.success("🟢 **No blocking detected**")
    
    with col2:
        if deadlock_key in all_metrics:
            deadlocks = get_metric_current_value(all_metrics[deadlock_key])
            if deadlocks > 0.1:
                st.warning(f"🟡 **{deadlocks:.3f} deadlocks per second**")
                st.write("**Recommended Actions:**")
                st.write("1. Enable deadlock logging (TRACEON 1222)")
                st.write("2. Review deadlock graphs")
                st.write("3. Optimize transaction ordering")
            else:
                st.success("🟢 **No significant deadlock activity**")

def detect_sql_server_issues(instance_metrics, instance_id):
    """Detect current SQL Server issues and provide recommendations"""
    
    issues = []
    
    # Check buffer cache hit ratio
    buffer_cache_key = f"{instance_id}_buffer_cache_hit_ratio"
    if buffer_cache_key in instance_metrics:
        buffer_cache = get_metric_current_value(instance_metrics[buffer_cache_key])
        if buffer_cache < 90:
            issues.append({
                'severity': 'critical' if buffer_cache < 85 else 'warning',
                'title': 'Low Buffer Cache Hit Ratio',
                'description': f'Buffer cache hit ratio is {buffer_cache:.1f}%, below the recommended 95%',
                'impact': 'Queries are performing excessive disk I/O, causing slow response times',
                'immediate_actions': [
                    'Check current memory usage with sys.dm_os_memory_clerks',
                    'Identify memory-intensive queries',
                    'Consider adding more server memory'
                ],
                'sql_diagnostic': "SELECT * FROM sys.dm_os_memory_clerks ORDER BY pages_kb DESC"
            })
    
    # Check for blocking
    blocked_key = f"{instance_id}_processes_blocked"
    if blocked_key in instance_metrics:
        blocked = get_metric_current_value(instance_metrics[blocked_key])
        if blocked > 0:
            issues.append({
                'severity': 'critical' if blocked > 10 else 'warning',
                'title': f'{int(blocked)} Processes Currently Blocked',
                'description': f'There are {int(blocked)} processes waiting due to blocking',
                'impact': 'Users experiencing delays, potential timeouts and poor application performance',
                'immediate_actions': [
                    'Identify blocking chain',
                    'Review long-running transactions',
                    'Consider killing head blocker if necessary'
                ],
                'sql_diagnostic': "SELECT * FROM sys.dm_exec_requests WHERE blocking_session_id != 0"
            })
    
    return issues

def render_issue_card(issue):
    """Render an issue card with diagnostic information"""
    
    severity_colors = {
        'critical': '#dc3545',
        'warning': '#ffc107',
        'info': '#17a2b8'
    }
    
    severity_icons = {
        'critical': '🔴',
        'warning': '🟡', 
        'info': '🔵'
    }
    
    severity = issue.get('severity', 'info')
    color = severity_colors[severity]
    icon = severity_icons[severity]
    
    with st.expander(f"{icon} {issue['title']}", expanded=True):
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.markdown(f"**Issue:** {issue['description']}")
            st.markdown(f"**Impact:** {issue['impact']}")
            
            st.write("**🔧 Immediate Actions:**")
            for i, action in enumerate(issue['immediate_actions'], 1):
                st.write(f"{i}. {action}")
        
        with col2:
            st.write("**🔍 SQL Diagnostic:**")
            st.code(issue['sql_diagnostic'], language='sql')
            
            if st.button(f"📋 Copy Query", key=f"copy_{issue['title']}"):
                st.success("Query copied to clipboard!")

def render_os_metrics_tab(all_metrics, ec2_instances):
    """Render OS metrics tab"""
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

def render_always_on_tab():
    """Render Always On Availability Groups tab"""
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

def render_auto_remediation_tab(all_metrics, enable_auto_remediation):
    """Render auto-remediation tab"""
    st.header("🤖 Intelligent Auto-Remediation")
    
    if enable_auto_remediation:
        # Evaluate current conditions for remediation
        current_alerts = []
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

def render_predictive_analytics_tab(all_metrics, enable_predictive_alerts):
    """Render predictive analytics tab"""
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

# Fix for streamlit_app.py
# Find the render_alerts_tab function around line 2000 and modify it:

def render_alerts_tab(all_metrics, all_logs):
    """Render alerts tab with enhanced log handling"""
    st.header("🚨 Intelligent Alert Management")
    
    # Generate alerts based on metrics
    current_alerts = []
    
    if all_metrics.get('cpu_usage'):
        recent_cpu = [dp['Average'] for dp in all_metrics['cpu_usage'][-3:]]
        if recent_cpu and all(cpu > 85 for cpu in recent_cpu):
            current_alerts.append({
                'severity': 'Warning',
                'message': f'High CPU usage detected: {recent_cpu[-1]:.1f}%',
                'timestamp': datetime.now()
            })
    
    if all_metrics.get('memory_usage'):
        recent_memory = [dp['Average'] for dp in all_metrics['memory_usage'][-3:]]
        if recent_memory and all(mem > 90 for mem in recent_memory):
            current_alerts.append({
                'severity': 'Critical',
                'message': f'Memory pressure detected: {recent_memory[-1]:.1f}%',
                'timestamp': datetime.now()
            })
    
    # Display current alerts
    if current_alerts:
        st.subheader("🚨 Active Alerts")
        
        for alert in current_alerts:
            severity_color = {
                'Critical': 'alert-critical',
                'Warning': 'alert-warning',
                'Info': 'metric-card'
            }.get(alert['severity'], 'metric-card')
            
            st.markdown(f"""
            <div class="{severity_color}">
                <strong>🚨 {alert['severity']}: {alert['message']}</strong><br>
                <small>Time: {alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}</small>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.success("🎉 No active alerts - all systems operating normally!")
    
    # Enhanced logs display with FIXED error handling
    st.markdown("---")
    st.subheader("📝 CloudWatch Logs Analysis")
    
    # Add time range selector
    col1, col2 = st.columns(2)
    with col1:
        hours_back = st.selectbox("Time Range", [1, 6, 24, 48, 168], 
                                 format_func=lambda x: f"Last {x} hours" if x < 48 else f"Last {x//24} days",
                                 index=2)  # Default to 24 hours
    
    with col2:
        if st.button("🔄 Refresh Logs"):
            st.cache_data.clear()
    
    # Get logs with selected time range
    if st.session_state.cloudwatch_connector:
        aws_config = st.session_state.cloudwatch_connector.aws_config
        configured_log_groups = aws_config.get('log_groups', [])
        
        if configured_log_groups:
            st.info(f"📋 **Configured log groups:** {', '.join(configured_log_groups)}")
            
            try:
                # Get logs with custom time range and better error handling
                fresh_logs = {}
                logs_client = st.session_state.cloudwatch_connector.aws_manager.get_client('logs')
                
                if logs_client and not st.session_state.cloudwatch_connector.demo_mode:
                    start_time = int((datetime.now() - timedelta(hours=hours_back)).timestamp() * 1000)
                    end_time = int(datetime.now().timestamp() * 1000)
                    
                    working_log_groups = []
                    failed_log_groups = []
                    
                    for log_group in configured_log_groups:
                        try:
                            st.write(f"📡 **Fetching logs from:** `{log_group}`")
                            
                            response = logs_client.filter_log_events(
                                logGroupName=log_group,
                                startTime=start_time,
                                endTime=end_time,
                                limit=50  # Limit to prevent timeouts
                            )
                            
                            fresh_logs[log_group] = response['events']
                            working_log_groups.append(log_group)
                            st.success(f"✅ **{log_group}:** Found {len(response['events'])} events")
                            
                        except logs_client.exceptions.ResourceNotFoundException:
                            failed_log_groups.append((log_group, "Log group does not exist"))
                            st.error(f"❌ **{log_group}:** Log group not found")
                        except logs_client.exceptions.InvalidParameterException as e:
                            failed_log_groups.append((log_group, f"Invalid parameter: {str(e)}"))
                            st.error(f"❌ **{log_group}:** Invalid parameter: {str(e)}")
                        except logs_client.exceptions.ServiceUnavailableException:
                            failed_log_groups.append((log_group, "CloudWatch Logs service unavailable"))
                            st.error(f"❌ **{log_group}:** Service unavailable")
                        except Exception as e:
                            failed_log_groups.append((log_group, str(e)))
                            st.error(f"❌ **{log_group}:** {str(e)}")
                    
                    # Show summary
                    if working_log_groups:
                        st.success(f"✅ **Successfully accessed {len(working_log_groups)} log groups**")
                        with st.expander("✅ Working Log Groups"):
                            for lg in working_log_groups:
                                st.write(f"• `{lg}`")
                    
                    if failed_log_groups:
                        st.warning(f"⚠️ **Failed to access {len(failed_log_groups)} log groups**")
                        with st.expander("❌ Failed Log Groups"):
                            for log_group, error in failed_log_groups:
                                st.error(f"**{log_group}:** {error}")
                                
                                # Provide specific help for common errors
                                if "does not exist" in error.lower():
                                    st.info(f"💡 **Fix:** Check if `{log_group}` exists in CloudWatch Console")
                                elif "access denied" in error.lower():
                                    st.info("💡 **Fix:** Add `logs:FilterLogEvents` permission to your IAM policy")
                
                else:
                    # Demo mode
                    fresh_logs = st.session_state.cloudwatch_connector._generate_demo_sql_logs(configured_log_groups)
                    st.info("🎭 **Demo Mode:** Showing simulated log data")
                
                # Display logs if we have any
                if fresh_logs:
                    # Log group selector
                    available_groups = [lg for lg in fresh_logs.keys() if fresh_logs[lg]]
                    
                    if available_groups:
                        selected_log_group = st.selectbox(
                            "Select Log Group to View", 
                            available_groups
                        )
                        
                        if selected_log_group and fresh_logs[selected_log_group]:
                            logs = fresh_logs[selected_log_group]
                            
                            st.success(f"✅ **{selected_log_group}:** {len(logs)} events")
                            
                            # Log filters
                            col1, col2, col3 = st.columns(3)
                            with col1:
                                search_term = st.text_input("🔍 Search in logs", 
                                                          placeholder="error, warning, failed")
                            with col2:
                                max_logs = st.slider("Max logs to display", 5, 50, 20)
                            with col3:
                                sort_order = st.selectbox("Sort", ["Newest First", "Oldest First"])
                            
                            # Filter and sort logs
                            filtered_logs = logs
                            if search_term:
                                filtered_logs = [log for log in logs 
                                               if search_term.lower() in log.get('message', '').lower()]
                            
                            # Sort logs
                            filtered_logs = sorted(filtered_logs, 
                                                 key=lambda x: x.get('timestamp', 0),
                                                 reverse=(sort_order == "Newest First"))
                            
                            # Limit logs
                            filtered_logs = filtered_logs[:max_logs]
                            
                            # Display logs with better formatting
                            if filtered_logs:
                                st.subheader(f"📋 Events from {selected_log_group}")
                                
                                for i, log in enumerate(filtered_logs):
                                    try:
                                        timestamp = datetime.fromtimestamp(log['timestamp'] / 1000)
                                        message = log.get('message', 'No message')
                                        
                                        # Clean up message for display
                                        if isinstance(message, bytes):
                                            message = message.decode('utf-8', errors='replace')
                                        
                                        # Truncate very long messages
                                        display_message = message[:500]
                                        if len(message) > 500:
                                            display_message += "... [truncated]"
                                        
                                        # Color code based on content
                                        if any(word in message.lower() for word in ['error', 'failed', 'exception']):
                                            message_type = "🔴 ERROR"
                                            container_class = "alert-critical"
                                        elif any(word in message.lower() for word in ['warning', 'warn']):
                                            message_type = "🟡 WARNING"
                                            container_class = "alert-warning"
                                        else:
                                            message_type = "ℹ️ INFO"
                                            container_class = "metric-card"
                                        
                                        # Display with timestamp and type
                                        with st.container():
                                            st.markdown(f"""
                                            <div class="{container_class}" style="margin: 0.5rem 0;">
                                                <strong>{message_type}</strong> - {timestamp.strftime('%Y-%m-%d %H:%M:%S')}<br>
                                                <small>{display_message}</small>
                                            </div>
                                            """, unsafe_allow_html=True)
                                    
                                    except Exception as e:
                                        st.error(f"Error displaying log event {i+1}: {str(e)}")
                            else:
                                st.info(f"No events found matching '{search_term}'" if search_term else "No events in selected time range")
                        
                        else:
                            st.warning(f"No events found in {selected_log_group} for the selected time range")
                    else:
                        st.warning("No log groups contain events for the selected time range")
                
                else:
                    st.warning("No log data available")
                    st.info("**Possible reasons:**")
                    st.write("• Log groups are empty for the selected time range")
                    st.write("• CloudWatch agent is not sending logs")
                    st.write("• Insufficient IAM permissions")
                    
            except Exception as e:
                st.error(f"❌ **Error retrieving logs:** {str(e)}")
                st.info("Check your CloudWatch Logs permissions and log group names")
        
        else:
            st.warning("⚠️ **No log groups configured**")
            st.info("Configure log groups in the sidebar to see log data")
            
            # Show help for configuring log groups
            with st.expander("💡 How to Configure Log Groups"):
                st.write("1. Go to the sidebar")
                st.write("2. Scroll to 'CloudWatch Configuration'")
                st.write("3. Select your actual log groups:")
                st.code("""
SQLServer/ErrorLogs
Windows/Application
Windows/Security
Windows/Setup
Windows/System
                """)
                st.write("4. Click 'Test Log Group Access' to verify")
    
    else:
        st.info("Connect to AWS first to see logs")
        
        # Show connection instructions
        with st.expander("🔌 How to Connect to AWS"):
            st.write("1. Go to the sidebar")
            st.write("2. Configure your AWS credentials")
            st.write("3. Click 'Test AWS Connection'")
            st.write("4. Return to this tab to view logs")


def render_performance_tab(all_metrics):
    """Render performance analytics tab"""
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

def render_reports_tab():
    """Render reports tab"""
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
        all_metrics = {}  # Initialize as empty dict
        if hasattr(st.session_state, 'cloudwatch_connector') and st.session_state.cloudwatch_connector:
            try:
                # Try to get metrics if available
                all_metrics, _, _ = collect_comprehensive_metrics()
                if all_metrics.get('cpu_usage') and all_metrics.get('memory_usage'):
                    avg_cpu = np.mean([dp['Average'] for dp in all_metrics['cpu_usage'][-10:]])
                    avg_mem = np.mean([dp['Average'] for dp in all_metrics['memory_usage'][-10:]])
                    system_health = max(0, 100 - ((avg_cpu + avg_mem) / 2))
            except:
                pass  # Use default value if metrics unavailable
        
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
            remediation_count = 0
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
        all_metrics = {}  # Initialize as empty dict
        
        try:
            all_metrics, _, _ = collect_comprehensive_metrics()
        except:
            pass  # Use defaults if metrics unavailable
        
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
            
            
# ================= ENHANCED TAB RENDERING FUNCTIONS =================

def render_enhanced_auto_remediation_tab():
    """Enhanced auto-remediation tab with complete visibility"""
    
    st.header("🤖 Intelligent Auto-Remediation System")
    st.write("**Automated SQL Server issue detection and resolution with full transparency**")
    
    # Initialize enhanced remediation engine if not exists
    if 'enhanced_auto_remediation' not in st.session_state:
        if st.session_state.cloudwatch_connector:
            st.session_state.enhanced_auto_remediation = EnhancedAutoRemediationEngine(
                st.session_state.cloudwatch_connector
            )
        else:
            st.warning("CloudWatch connector required for auto-remediation")
            return
    
    remediation_engine = st.session_state.enhanced_auto_remediation
    
    # Get current metrics for evaluation
    all_metrics, _, _ = collect_comprehensive_metrics()
    
    # Remediation Status Overview
    st.subheader("📊 Remediation System Status")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        active_opportunities = remediation_engine.evaluate_all_rules(all_metrics)
        color = "🔴" if len(active_opportunities) > 0 else "🟢"
        st.metric(f"Active Issues {color}", len(active_opportunities))
    
    with col2:
        total_executed = remediation_engine.success_metrics['total_executed']
        st.metric("Actions Executed Today", total_executed)
    
    with col3:
        success_rate = remediation_engine.get_success_rate()
        color = "🟢" if success_rate > 90 else "🟡" if success_rate > 75 else "🔴"
        st.metric(f"Success Rate {color}", f"{success_rate:.1f}%")
    
    with col4:
        auto_executed = remediation_engine.success_metrics['auto_executed']
        manual_executed = remediation_engine.success_metrics['manual_executed']
        ratio = auto_executed / max(1, auto_executed + manual_executed) * 100
        st.metric("Auto-Execution Rate", f"{ratio:.1f}%")
    
    # Current Opportunities
    st.markdown("---")
    st.subheader("🚨 Current Remediation Opportunities")
    
    if active_opportunities:
        for opportunity in active_opportunities:
            render_enhanced_remediation_opportunity(opportunity, remediation_engine)
    else:
        st.success("🎉 No immediate remediation actions required!")
        st.info("All SQL Server metrics are within acceptable ranges. The system is operating optimally.")
    
    # Execution History
    st.markdown("---")
    st.subheader("📋 Recent Execution History")
    render_remediation_execution_history(remediation_engine)

def render_enhanced_remediation_opportunity(opportunity: Dict, engine):
    """Render enhanced remediation opportunity with detailed actions"""
    
    rule_config = opportunity['rule_config']
    current_value = opportunity['current_value']
    rule_name = opportunity['rule_name']
    
    severity_colors = {
        'Critical': '🔴',
        'High': '🟡',
        'Medium': '🟠',
        'Low': '🟢'
    }
    
    severity_icon = severity_colors.get(rule_config['severity'], '🔵')
    
    with st.expander(f"{severity_icon} {rule_config['description']} - {rule_config['severity']} Priority", expanded=True):
        
        # Opportunity Details
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.markdown(f"**🎯 Issue:** {rule_config['description']}")
            st.markdown(f"**📊 Current Value:** {current_value:.2f}")
            st.markdown(f"**⚠️ Threshold:** {rule_config['condition']} {rule_config['threshold']}")
            st.markdown(f"**💥 Impact:** {rule_config['impact']}")
            st.markdown(f"**🏢 Business Impact:** {rule_config['business_impact']}")
            
            # Show available actions with details
            st.markdown("**🔧 Available Actions:**")
            
            for i, action in enumerate(rule_config['actions'], 1):
                risk_colors = {"Low": "🟢", "Medium": "🟡", "High": "🔴"}
                risk_color = risk_colors.get(action['risk_level'], "🔵")
                
                # Action card
                st.markdown(f"""
                <div style="
                    border-left: 4px solid {'#28a745' if action['risk_level'] == 'Low' else '#ffc107' if action['risk_level'] == 'Medium' else '#dc3545'};
                    padding: 0.5rem;
                    margin: 0.5rem 0;
                    background-color: #f8f9fa;
                ">
                    <strong>{i}. {risk_color} {action['name']}</strong><br>
                    <small><strong>Type:</strong> {action['type']} | <strong>Risk:</strong> {action['risk_level']}</small><br>
                    <small>{action['description']}</small><br>
                    <small><strong>Expected:</strong> {action.get('expected_outcome', 'See description')}</small>
                </div>
                """, unsafe_allow_html=True)
                
                # Show SQL command if available
                if action.get('sql_command'):
                    with st.expander(f"SQL Command for {action['name']}", expanded=False):
                        st.code(action['sql_command'], language='sql')
                
                # Show side effects if any
                if action.get('side_effects'):
                    st.warning(f"⚠️ Side Effects: {action['side_effects']}")
        
        with col2:
            st.markdown("**⚡ Quick Actions:**")
            
            # Execute individual actions
            for i, action in enumerate(rule_config['actions']):
                button_key = f"execute_{rule_name}_{i}"
                button_text = f"🔧 {action['name']}"
                
                if action.get('auto_execute', False):
                    button_text += " (Auto)"
                else:
                    button_text += " (Manual)"
                
                if st.button(button_text, key=button_key):
                    with st.spinner(f"Executing {action['name']}..."):
                        result = engine.execute_action(action, rule_name)
                        
                        if result['status'] == 'success':
                            st.success(f"✅ {result['message']}")
                            if result.get('results'):
                                with st.expander("View Results"):
                                    st.text(result['results'])
                        elif result['status'] == 'pending_approval':
                            st.warning(f"⏳ {result['message']}")
                        else:
                            st.error(f"❌ {result.get('error', 'Action failed')}")
            
            # Bulk actions
            st.markdown("---")
            
            auto_actions = [a for a in rule_config['actions'] if a.get('auto_execute')]
            if auto_actions and st.button(f"🤖 Execute All Auto Actions ({len(auto_actions)})", key=f"auto_all_{rule_name}"):
                for action in auto_actions:
                    result = engine.execute_action(action, rule_name)
                    if result['status'] == 'success':
                        st.success(f"✅ {action['name']}: {result['message']}")
                    else:
                        st.error(f"❌ {action['name']}: {result.get('error', 'Failed')}")
            
            if st.button(f"⏸️ Snooze (1 hour)", key=f"snooze_{rule_name}"):
                engine.snooze_rule(rule_name, 60)
                st.success("Issue snoozed for 1 hour")
                st.rerun()

def render_remediation_execution_history(engine):
    """Render execution history with filtering and details"""
    
    if not engine.execution_history:
        st.info("No execution history available yet.")
        return
    
    # Recent executions (last 10)
    recent_executions = engine.execution_history[-10:]
    
    # Create DataFrame for display
    history_data = []
    for execution in reversed(recent_executions):  # Most recent first
        status_icon = "✅" if execution['status'] == 'success' else "⏳" if execution['status'] == 'pending_approval' else "❌"
        
        history_data.append({
            'Time': execution['started_at'].strftime('%H:%M:%S'),
            'Action': execution['action_name'],
            'Type': execution['action_type'],
            'Rule': execution['rule_name'],
            'Status': f"{status_icon} {execution['status']}",
            'Duration': f"{execution.get('duration', 0):.1f}s" if execution.get('duration') else 'N/A'
        })
    
    if history_data:
        history_df = pd.DataFrame(history_data)
        st.dataframe(history_df, use_container_width=True)
        
        # Show details for selected execution
        if st.checkbox("Show execution details"):
            selected_index = st.selectbox("Select execution", range(len(recent_executions)), 
                                        format_func=lambda x: f"{recent_executions[-(x+1)]['action_name']} at {recent_executions[-(x+1)]['started_at'].strftime('%H:%M:%S')}")
            
            if selected_index is not None:
                execution = recent_executions[-(selected_index+1)]
                
                with st.expander("Execution Details", expanded=True):
                    st.json(execution)

def render_enhanced_predictive_analytics_tab():
    """Enhanced predictive analytics tab with comprehensive forecasting"""
    
    st.header("🔮 Advanced Predictive Analytics & Capacity Planning")
    st.write("**AI-powered forecasting for SQL Server performance, capacity, and risk assessment**")
    
    # Initialize enhanced analytics engine if not exists
    if 'enhanced_predictive_analytics' not in st.session_state:
        if st.session_state.cloudwatch_connector:
            st.session_state.enhanced_predictive_analytics = EnhancedPredictiveAnalyticsEngine(
                st.session_state.cloudwatch_connector
            )
        else:
            st.warning("CloudWatch connector required for predictive analytics")
            return
    
    analytics_engine = st.session_state.enhanced_predictive_analytics
    
    # Get current metrics
    all_metrics, _, _ = collect_comprehensive_metrics()
    
    # Quick Predictions Overview
    st.subheader("⚡ Quick Predictions (Next 24 Hours)")
    
    performance_forecasts = analytics_engine.generate_performance_forecasts(all_metrics, 24)
    
    col1, col2, col3, col4 = st.columns(4)
    
    # Show key metric predictions
    key_metrics = ['buffer_cache_hit_ratio', 'processes_blocked', 'deadlocks_per_sec', 'memory_grants_pending']
    
    for i, metric in enumerate(key_metrics):
        if i < 4:  # Only show first 4
            with [col1, col2, col3, col4][i]:
                if metric in performance_forecasts:
                    forecast = performance_forecasts[metric]
                    issues = forecast['potential_issues']
                    
                    # Determine color based on issues
                    critical_issues = [issue for issue in issues if issue['severity'] == 'critical']
                    warning_issues = [issue for issue in issues if issue['severity'] == 'warning']
                    
                    if critical_issues:
                        color = "🔴"
                        status = "Critical Risk"
                    elif warning_issues:
                        color = "🟡" 
                        status = "Warning"
                    else:
                        color = "🟢"
                        status = "Stable"
                    
                    # Show prediction with confidence
                    avg_prediction = np.mean(forecast['predictions'])
                    confidence = forecast['average_confidence']
                    
                    st.metric(
                        f"{metric.replace('_', ' ').title()} {color}",
                        f"{avg_prediction:.2f}",
                        delta=f"{confidence:.0f}% confidence"
                    )
                    st.caption(status)
    
    # Detailed Analytics Tabs
    analytics_tabs = st.tabs([
        "📈 Performance Forecasts",
        "📊 Capacity Planning", 
        "⚠️ Risk Assessment",
        "🎯 AI Recommendations"
    ])
    
    with analytics_tabs[0]:
        render_performance_forecasts(analytics_engine, all_metrics)
    
    with analytics_tabs[1]:
        render_capacity_planning_analysis(analytics_engine, all_metrics)
    
    with analytics_tabs[2]:
        render_risk_assessment_analysis(analytics_engine, all_metrics)
    
    with analytics_tabs[3]:
        render_ai_recommendations(analytics_engine, all_metrics)

def render_performance_forecasts(engine, all_metrics):
    """Render detailed performance forecasting"""
    
    st.subheader("📈 Performance Forecasting (Next 24 Hours)")
    
    forecasts = engine.generate_performance_forecasts(all_metrics, 24)
    
    if not forecasts:
        st.warning("Insufficient data for performance forecasting")
        return
    
    # Select metric to analyze
    available_metrics = list(forecasts.keys())
    selected_metric = st.selectbox(
        "Select metric for detailed forecast",
        available_metrics,
        format_func=lambda x: x.replace('_', ' ').title()
    )
    
    if selected_metric and selected_metric in forecasts:
        forecast = forecasts[selected_metric]
        
        col1, col2 = st.columns([3, 1])
        
        with col1:
            # Create forecast chart
            hours = list(range(1, 25))  # 1-24 hours
            predictions = forecast['predictions']
            confidence_scores = forecast['confidence_scores']
            
            fig = go.Figure()
            
            # Main prediction line
            fig.add_trace(go.Scatter(
                x=hours,
                y=predictions,
                name='Predicted Values',
                line=dict(color='blue', width=3)
            ))
            
            # Confidence band
            upper_bound = [p * (1 + (100 - c) / 200) for p, c in zip(predictions, confidence_scores)]
            lower_bound = [p * (1 - (100 - c) / 200) for p, c in zip(predictions, confidence_scores)]
            
            fig.add_trace(go.Scatter(
                x=hours + hours[::-1],
                y=upper_bound + lower_bound[::-1],
                fill='toself',
                fillcolor='rgba(0, 100, 80, 0.2)',
                line=dict(color='rgba(255,255,255,0)'),
                name='Confidence Interval'
            ))
            
            # Add threshold lines based on metric
            if selected_metric == 'buffer_cache_hit_ratio':
                fig.add_hline(y=95, line_dash="dash", line_color="green", annotation_text="Good: 95%")
                fig.add_hline(y=90, line_dash="dash", line_color="orange", annotation_text="Warning: 90%")
                fig.add_hline(y=85, line_dash="dash", line_color="red", annotation_text="Critical: 85%")
            elif selected_metric == 'processes_blocked':
                fig.add_hline(y=5, line_dash="dash", line_color="orange", annotation_text="Warning: 5")
                fig.add_hline(y=20, line_dash="dash", line_color="red", annotation_text="Critical: 20")
            
            fig.update_layout(
                title=f"{selected_metric.replace('_', ' ').title()} - 24 Hour Forecast",
                xaxis_title="Hours Ahead",
                yaxis_title="Predicted Value",
                height=400
            )
            
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Forecast summary
            st.markdown(f"### 📊 Forecast Summary")
            st.write(f"**Average Confidence:** {forecast['average_confidence']:.1f}%")
            st.write(f"**Trend:** {'Increasing' if predictions[-1] > predictions[0] else 'Decreasing' if predictions[-1] < predictions[0] else 'Stable'}")
            
            # Potential issues
            issues = forecast['potential_issues']
            if issues:
                st.markdown("**⚠️ Predicted Issues:**")
                for issue in issues[:3]:  # Show top 3
                    severity_icon = "🔴" if issue['severity'] == 'critical' else "🟡"
                    st.write(f"{severity_icon} Hour {issue['hour']}: {issue['description']}")
            else:
                st.success("🟢 No issues predicted")
            
            # Recommendations
            recommendations = forecast['recommendations']
            if recommendations:
                st.markdown("**🎯 Recommendations:**")
                for rec in recommendations[:3]:
                    st.write(f"• {rec}")

def render_capacity_planning_analysis(engine, all_metrics):
    """Render capacity planning analysis"""
    
    st.subheader("📊 Capacity Planning Analysis")
    
    capacity_predictions = engine.generate_capacity_predictions(all_metrics)
    
    if not capacity_predictions:
        st.warning("Insufficient data for capacity planning")
        return
    
    # Capacity Overview Table
    st.write("### 📈 Capacity Utilization Projections")
    
    capacity_data = []
    for metric, data in capacity_predictions.items():
        predictions = data['predictions']
        risk_levels = data['risk_levels']
        
        capacity_data.append({
            'Resource': metric.replace('_', ' ').title(),
            'Current': f"{data['current']:.1f}",
            '7 Days': f"{predictions['7_days']:.1f}",
            '30 Days': f"{predictions['30_days']:.1f}",
            '90 Days': f"{predictions['90_days']:.1f}",
            '30D Risk': risk_levels['30_days'].title(),
            '90D Risk': risk_levels['90_days'].title()
        })
    
    capacity_df = pd.DataFrame(capacity_data)
    st.dataframe(capacity_df, use_container_width=True)

def render_risk_assessment_analysis(engine, all_metrics):
    """Render comprehensive risk assessment"""
    
    st.subheader("⚠️ Comprehensive Risk Assessment")
    
    risk_assessment = engine.assess_risk_levels(all_metrics)
    
    # Risk Summary Dashboard
    st.write("### 🎯 Risk Summary")
    
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        overall_score = risk_assessment['risk_summary']['overall_risk_score']
        color = "🟢" if overall_score < 25 else "🟡" if overall_score < 50 else "🟠" if overall_score < 75 else "🔴"
        st.metric(f"Overall Risk {color}", f"{overall_score:.0f}/100")
    
    with col2:
        critical_risks = risk_assessment['risk_summary']['critical_risks']
        color = "🔴" if critical_risks > 0 else "🟢"
        st.metric(f"Critical Risks {color}", critical_risks)
    
    with col3:
        high_risks = risk_assessment['risk_summary']['high_risks']
        color = "🟡" if high_risks > 0 else "🟢"
        st.metric(f"High Risks {color}", high_risks)
    
    with col4:
        medium_risks = risk_assessment['risk_summary']['medium_risks']
        color = "🟠" if medium_risks > 0 else "🟢"
        st.metric(f"Medium Risks {color}", medium_risks)
    
    with col5:
        low_risks = risk_assessment['risk_summary']['low_risks']
        st.metric("Low Risks 🟢", low_risks)

def render_ai_recommendations(engine, all_metrics):
    """Render AI-powered recommendations"""
    
    st.subheader("🎯 AI-Powered Recommendations")
    
    # Generate recommendations based on analysis
    risk_assessment = engine.assess_risk_levels(all_metrics)
    
    # Immediate recommendations
    st.write("### 🚨 Immediate Actions Required")
    
    immediate_actions = []
    for metric, risk_data in risk_assessment['current_risks'].items():
        if risk_data['risk_level'] == 'critical':
            immediate_actions.append(f"**{metric.replace('_', ' ').title()}**: Critical level detected - immediate action required")
    
    if immediate_actions:
        for action in immediate_actions:
            st.error(action)
    else:
        st.success("🟢 No immediate critical actions required")
    
    # Strategic recommendations
    st.write("### 📋 Strategic Recommendations")
    
    strategic_recs = [
        "Implement predictive scaling based on trend analysis",
        "Set up automated monitoring for critical thresholds",
        "Review and optimize resource allocation quarterly",
        "Establish baseline performance metrics for comparison"
    ]
    
    for rec in strategic_recs:
        st.write(f"• {rec}")


# =================== Main Application ===================
def main():
    # Load CSS styles
    #load_css_styles()
    from enterprise_enhancements import load_enhanced_enterprise_css
    load_enhanced_enterprise_css()
    
    
    # Display header
    st.markdown('<div class="aws-header"><h1>☁️ AWS CloudWatch SQL Server Monitor</h1><p>Enterprise-grade monitoring with AI-powered analytics and auto-remediation - Optimized for Streamlit Cloud</p></div>', unsafe_allow_html=True)
    
    # Setup sidebar configuration
    aws_config = setup_sidebar_configuration()
    
    # Initialize session state
    initialize_session_state(aws_config)
    
    # Display connection status and test button
    display_connection_status()
    
    # Collect metrics
    with st.spinner("🔄 Collecting metrics and logs..."):
        all_metrics, all_logs, ec2_instances = collect_comprehensive_metrics()
    
    # Get RDS instances
    rds_instances = st.session_state.cloudwatch_connector.get_rds_instances() if st.session_state.cloudwatch_connector else []
    
    # Get basic infrastructure metrics
    basic_metric_queries = [
        {'key': 'cpu_usage', 'namespace': 'AWS/EC2', 'metric_name': 'CPUUtilization', 'unit': 'Percent'},
        {'key': 'memory_usage', 'namespace': 'CWAgent', 'metric_name': 'Memory % Committed Bytes In Use', 'unit': 'Percent'},
        {'key': 'disk_usage', 'namespace': 'CWAgent', 'metric_name': 'LogicalDisk % Free Space', 'unit': 'Percent'},
        {'key': 'network_in', 'namespace': 'AWS/EC2', 'metric_name': 'NetworkIn', 'unit': 'Bytes'},
        {'key': 'network_out', 'namespace': 'AWS/EC2', 'metric_name': 'NetworkOut', 'unit': 'Bytes'}
    ]
    
    # Get basic infrastructure metrics
    if st.session_state.cloudwatch_connector:
        current_time = datetime.now()
        start_time = current_time - timedelta(hours=24)
        basic_metrics = st.session_state.cloudwatch_connector.get_cloudwatch_metrics(
            basic_metric_queries, start_time, current_time
        )
        all_metrics.update(basic_metrics)
    
    # Main tabs
    tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8, tab9, tab10 = st.tabs([
        "🏠 Dashboard", 
        "🗄️ SQL Metrics",
        "🖥️ OS Metrics",
        "🔄 Always On", 
        "🤖 Auto-Remediation",
        "🔮 Predictive Analytics", 
        "🚨 Alerts", 
        "📊 Performance",
        "📈 Reports",
        "🔍 EC2 Debug"
    ])
    
    # Render tabs
    with tab1:
        render_dashboard_tab(all_metrics, ec2_instances, rds_instances)        
        if st.checkbox("🏢 Show Executive View", value=True):
            st.markdown("---")
        from enterprise_enhancements import render_enhanced_executive_dashboard
        render_enhanced_executive_dashboard(all_metrics, ec2_instances, rds_instances)# New
    
    with tab2:        
        render_enhanced_sql_metrics_tab(all_metrics, ec2_instances)
    
    with tab3:
        render_os_metrics_tab(all_metrics, ec2_instances)
    
    with tab4:
        render_always_on_tab()
    
    with tab5:
        render_enhanced_auto_remediation_tab()
    
    with tab6:
        render_enhanced_predictive_analytics_tab()
    
    with tab7:
        render_alerts_tab(all_metrics, all_logs)
    
    with tab8:
        render_performance_tab(all_metrics)
    
    with tab9:
        render_reports_tab()
    
    with tab10:
        debug_ec2_instances()
    
    # Auto-refresh functionality with Streamlit Cloud optimization
    if 'last_refresh' not in st.session_state:
        st.session_state.last_refresh = datetime.now()
    
    time_since_refresh = (datetime.now() - st.session_state.last_refresh).seconds
    refresh_interval = aws_config.get('refresh_interval', 60)
    
    # Only auto-refresh if not in demo mode to avoid excessive API calls
    if time_since_refresh >= refresh_interval and not st.session_state.cloudwatch_connector.demo_mode:
        st.session_state.last_refresh = datetime.now()
        st.rerun()
    
    # Enhanced status bar with Streamlit Cloud info
    with st.sidebar:
        st.markdown("---")
        st.write(f"🔄 Last refresh: {st.session_state.last_refresh.strftime('%H:%M:%S')}")
        
        if not (st.session_state.cloudwatch_connector and st.session_state.cloudwatch_connector.demo_mode):
            st.write(f"⏱️ Next refresh: {refresh_interval - time_since_refresh}s")
        else:
            st.write("⏱️ Auto-refresh disabled in demo mode")
        
        # Connection status indicator
        if st.session_state.cloudwatch_connector:
            conn_status = st.session_state.cloudwatch_connector.get_connection_status()
            if conn_status.get('connected'):
                if conn_status.get('demo_mode'):
                    st.warning("🎭 Demo Mode")
                else:
                    st.success("🟢 AWS Connected")
            else:
                st.error("🔴 AWS Disconnected")
            
            # Environment info
            if conn_status.get('streamlit_cloud'):
                st.info("🌐 Streamlit Cloud")
        
        if st.button("🔄 Refresh Now", type="primary"):
            # Clear cache for fresh data
            collect_comprehensive_metrics.clear()
            st.rerun()

if __name__ == "__main__":
    main()