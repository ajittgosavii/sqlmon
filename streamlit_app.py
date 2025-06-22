import streamlit as st
import boto3
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

warnings.filterwarnings('ignore')

# Configure Streamlit page
st.set_page_config(
    page_title="SQL Server AI Monitoring",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better UI
st.markdown("""
<style>
    .metric-card {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        margin: 0.5rem 0;
    }
    .alert-critical {
        background-color: #ff4444;
        color: white;
        padding: 0.5rem;
        border-radius: 5px;
        margin: 0.2rem 0;
    }
    .alert-warning {
        background-color: #ffaa00;
        color: white;
        padding: 0.5rem;
        border-radius: 5px;
        margin: 0.2rem 0;
    }
    .alert-info {
        background-color: #0099cc;
        color: white;
        padding: 0.5rem;
        border-radius: 5px;
        margin: 0.2rem 0;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 2px;
    }
    .stTabs [data-baseweb="tab"] {
        height: 50px;
        padding-left: 20px;
        padding-right: 20px;
    }
</style>
""", unsafe_allow_html=True)

# =================== AWS CloudWatch Integration ===================
class AWSCloudWatchConnector:
    def __init__(self, aws_access_key: str, aws_secret_key: str, region: str = 'us-east-1'):
        """Initialize AWS CloudWatch connection"""
        self.session = boto3.Session(
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )
        self.cloudwatch = self.session.client('cloudwatch')
        self.logs_client = self.session.client('logs')
        self.ssm_client = self.session.client('ssm')
    
    def get_metric_data(self, metric_queries: List[Dict], start_time: datetime, end_time: datetime) -> pd.DataFrame:
        """Retrieve metric data from CloudWatch"""
        try:
            response = self.cloudwatch.get_metric_data(
                MetricDataQueries=metric_queries,
                StartTime=start_time,
                EndTime=end_time
            )
            
            data = []
            for result in response['MetricDataResults']:
                for timestamp, value in zip(result['Timestamps'], result['Values']):
                    data.append({
                        'timestamp': timestamp,
                        'metric': result['Id'],
                        'value': value
                    })
            
            return pd.DataFrame(data)
        except Exception as e:
            st.error(f"Error fetching metrics: {str(e)}")
            return pd.DataFrame()
    
    def query_logs(self, log_group: str, query: str, start_time: datetime, end_time: datetime) -> List[Dict]:
        """Query CloudWatch Logs"""
        try:
            start_query_response = self.logs_client.start_query(
                logGroupName=log_group,
                startTime=int(start_time.timestamp()),
                endTime=int(end_time.timestamp()),
                queryString=query
            )
            
            query_id = start_query_response['queryId']
            
            # Wait for query completion
            while True:
                time.sleep(1)
                response = self.logs_client.get_query_results(queryId=query_id)
                if response['status'] == 'Complete':
                    return response['results']
                elif response['status'] == 'Failed':
                    st.error("Log query failed")
                    return []
                    
        except Exception as e:
            st.error(f"Error querying logs: {str(e)}")
            return []
    
    def send_custom_metric(self, namespace: str, metric_name: str, value: float, unit: str = 'Count'):
        """Send custom metric to CloudWatch"""
        try:
            self.cloudwatch.put_metric_data(
                Namespace=namespace,
                MetricData=[
                    {
                        'MetricName': metric_name,
                        'Value': value,
                        'Unit': unit,
                        'Timestamp': datetime.utcnow()
                    }
                ]
            )
        except Exception as e:
            st.error(f"Error sending metric: {str(e)}")

# =================== Machine Learning Models ===================
class SQLServerMLPredictor:
    def __init__(self):
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.failure_predictor = RandomForestClassifier(n_estimators=100, random_state=42)
        self.scaler = StandardScaler()
        self.is_trained = False
    
    def prepare_features(self, data: pd.DataFrame) -> np.ndarray:
        """Prepare features for ML models"""
        if data.empty:
            return np.array([])
        
        # Feature engineering
        features = []
        
        # Basic metrics
        if 'cpu_usage' in data.columns:
            features.extend([
                data['cpu_usage'].mean(),
                data['cpu_usage'].std(),
                data['cpu_usage'].max()
            ])
        
        # Memory metrics
        if 'memory_usage' in data.columns:
            features.extend([
                data['memory_usage'].mean(),
                data['memory_usage'].std(),
                data['memory_usage'].max()
            ])
        
        # SQL Server specific metrics
        sql_metrics = ['connections', 'lock_waits', 'buffer_cache_hit_ratio', 'page_life_expectancy']
        for metric in sql_metrics:
            if metric in data.columns:
                features.extend([
                    data[metric].mean(),
                    data[metric].std() if len(data) > 1 else 0
                ])
            else:
                features.extend([0, 0])  # Default values if metric not available
        
        # Time-based features
        if 'timestamp' in data.columns:
            data['hour'] = pd.to_datetime(data['timestamp']).dt.hour
            data['day_of_week'] = pd.to_datetime(data['timestamp']).dt.dayofweek
            features.extend([
                data['hour'].mode().iloc[0] if len(data) > 0 else 12,
                data['day_of_week'].mode().iloc[0] if len(data) > 0 else 1
            ])
        else:
            features.extend([12, 1])  # Default values
        
        return np.array(features).reshape(1, -1)
    
    def train_models(self, historical_data: pd.DataFrame):
        """Train ML models with historical data"""
        if historical_data.empty:
            st.warning("No historical data available for training")
            return
        
        # Prepare training data
        X = []
        y_anomaly = []
        y_failure = []
        
        # Group data by time windows
        historical_data['timestamp'] = pd.to_datetime(historical_data['timestamp'])
        historical_data = historical_data.sort_values('timestamp')
        
        # Create time windows (1-hour intervals)
        window_size = timedelta(hours=1)
        current_time = historical_data['timestamp'].min()
        end_time = historical_data['timestamp'].max()
        
        while current_time < end_time:
            window_end = current_time + window_size
            window_data = historical_data[
                (historical_data['timestamp'] >= current_time) & 
                (historical_data['timestamp'] < window_end)
            ]
            
            if not window_data.empty:
                features = self.prepare_features(window_data)
                if features.size > 0:
                    X.append(features[0])
                    
                    # Label generation (simplified - you should use actual failure data)
                    # Anomaly: high resource usage or error counts
                    is_anomaly = (
                        window_data.get('cpu_usage', pd.Series([0])).max() > 80 or
                        window_data.get('memory_usage', pd.Series([0])).max() > 85 or
                        window_data.get('error_count', pd.Series([0])).sum() > 0
                    )
                    y_anomaly.append(1 if is_anomaly else 0)
                    
                    # Failure prediction (look ahead 24 hours)
                    future_data = historical_data[
                        (historical_data['timestamp'] >= window_end) & 
                        (historical_data['timestamp'] < window_end + timedelta(hours=24))
                    ]
                    has_failure = future_data.get('failure', pd.Series([False])).any()
                    y_failure.append(1 if has_failure else 0)
            
            current_time = window_end
        
        if len(X) > 10:  # Minimum samples for training
            X = np.array(X)
            X = self.scaler.fit_transform(X)
            
            # Train anomaly detector
            self.anomaly_detector.fit(X)
            
            # Train failure predictor if we have enough positive samples
            if len(set(y_failure)) > 1:
                self.failure_predictor.fit(X, y_failure)
            
            self.is_trained = True
            st.success("ML models trained successfully!")
        else:
            st.warning("Insufficient data for model training")
    
    def predict_anomaly(self, current_data: pd.DataFrame) -> Dict[str, Any]:
        """Predict anomalies in current data"""
        if not self.is_trained:
            return {"anomaly_score": 0, "is_anomaly": False, "confidence": 0}
        
        features = self.prepare_features(current_data)
        if features.size == 0:
            return {"anomaly_score": 0, "is_anomaly": False, "confidence": 0}
        
        features_scaled = self.scaler.transform(features)
        anomaly_score = self.anomaly_detector.decision_function(features_scaled)[0]
        is_anomaly = self.anomaly_detector.predict(features_scaled)[0] == -1
        
        # Convert score to 0-100 scale
        confidence = min(100, max(0, abs(anomaly_score) * 20))
        
        return {
            "anomaly_score": anomaly_score,
            "is_anomaly": is_anomaly,
            "confidence": confidence
        }
    
    def predict_failure(self, current_data: pd.DataFrame) -> Dict[str, Any]:
        """Predict potential failures"""
        if not self.is_trained:
            return {"failure_probability": 0, "risk_level": "Unknown", "confidence": 0}
        
        features = self.prepare_features(current_data)
        if features.size == 0:
            return {"failure_probability": 0, "risk_level": "Unknown", "confidence": 0}
        
        features_scaled = self.scaler.transform(features)
        
        try:
            failure_prob = self.failure_predictor.predict_proba(features_scaled)[0][1]
        except:
            failure_prob = 0
        
        # Determine risk level
        if failure_prob > 0.7:
            risk_level = "Critical"
        elif failure_prob > 0.4:
            risk_level = "High"
        elif failure_prob > 0.2:
            risk_level = "Medium"
        else:
            risk_level = "Low"
        
        return {
            "failure_probability": failure_prob * 100,
            "risk_level": risk_level,
            "confidence": failure_prob * 100
        }

# =================== Data Generator (for demo purposes) ===================
class DataGenerator:
    """Generate synthetic SQL Server metrics for demonstration"""
    
    @staticmethod
    def generate_realtime_metrics(node_count: int = 3) -> Dict[str, pd.DataFrame]:
        """Generate real-time metrics for all nodes"""
        current_time = datetime.now()
        nodes_data = {}
        
        for node_id in range(1, node_count + 1):
            # Generate synthetic metrics with some randomness
            base_cpu = 45 + np.random.normal(0, 10)
            base_memory = 60 + np.random.normal(0, 15)
            
            # Add some correlation and patterns
            if node_id == 1:  # Primary replica might have higher load
                base_cpu += 15
                base_memory += 10
            
            data = {
                'timestamp': [current_time - timedelta(minutes=i) for i in range(30, 0, -1)],
                'cpu_usage': np.clip([base_cpu + np.random.normal(0, 5) for _ in range(30)], 0, 100),
                'memory_usage': np.clip([base_memory + np.random.normal(0, 8) for _ in range(30)], 0, 100),
                'disk_io': np.random.exponential(50, 30),
                'connections': np.random.poisson(100, 30),
                'lock_waits': np.random.exponential(5, 30),
                'buffer_cache_hit_ratio': np.clip(np.random.normal(95, 2, 30), 85, 100),
                'page_life_expectancy': np.random.normal(3000, 500, 30),
                'log_growth_rate': np.random.exponential(10, 30),
                'backup_size': np.random.normal(500, 100, 30),
                'network_io': np.random.exponential(25, 30)
            }
            
            nodes_data[f'Node_{node_id}'] = pd.DataFrame(data)
        
        return nodes_data
    
    @staticmethod
    def generate_historical_data(days: int = 30) -> pd.DataFrame:
        """Generate historical data for model training"""
        end_time = datetime.now()
        start_time = end_time - timedelta(days=days)
        
        timestamps = pd.date_range(start_time, end_time, freq='5T')
        n_samples = len(timestamps)
        
        # Generate patterns with some seasonality
        hours = np.array([t.hour for t in timestamps])
        daily_pattern = np.sin(2 * np.pi * hours / 24) * 10 + 50
        
        data = {
            'timestamp': timestamps,
            'cpu_usage': np.clip(daily_pattern + np.random.normal(0, 10, n_samples), 0, 100),
            'memory_usage': np.clip(daily_pattern + np.random.normal(10, 8, n_samples), 0, 100),
            'connections': np.random.poisson(100, n_samples),
            'lock_waits': np.random.exponential(5, n_samples),
            'buffer_cache_hit_ratio': np.clip(np.random.normal(95, 2, n_samples), 85, 100),
            'page_life_expectancy': np.random.normal(3000, 500, n_samples),
            'error_count': np.random.poisson(0.1, n_samples),  # Rare errors
            'failure': np.random.choice([True, False], n_samples, p=[0.001, 0.999])  # Very rare failures
        }
        
        return pd.DataFrame(data)

# =================== Alert Management System ===================
class AlertManager:
    def __init__(self):
        self.alert_rules = {
            'cpu_high': {'threshold': 80, 'severity': 'warning', 'message': 'High CPU usage detected'},
            'cpu_critical': {'threshold': 95, 'severity': 'critical', 'message': 'Critical CPU usage'},
            'memory_high': {'threshold': 85, 'severity': 'warning', 'message': 'High memory usage'},
            'memory_critical': {'threshold': 95, 'severity': 'critical', 'message': 'Critical memory usage'},
            'connections_high': {'threshold': 200, 'severity': 'warning', 'message': 'High connection count'},
            'buffer_cache_low': {'threshold': 90, 'severity': 'warning', 'message': 'Low buffer cache hit ratio'},
            'page_life_low': {'threshold': 300, 'severity': 'critical', 'message': 'Low page life expectancy'}
        }
        
        if 'alerts' not in st.session_state:
            st.session_state.alerts = []
    
    def evaluate_alerts(self, node_data: pd.DataFrame, node_name: str) -> List[Dict]:
        """Evaluate alert conditions"""
        alerts = []
        current_time = datetime.now()
        
        if node_data.empty:
            return alerts
        
        latest_data = node_data.iloc[-1]
        
        # Check CPU alerts
        if latest_data.get('cpu_usage', 0) > self.alert_rules['cpu_critical']['threshold']:
            alerts.append({
                'timestamp': current_time,
                'node': node_name,
                'severity': 'critical',
                'message': f"Critical CPU usage: {latest_data['cpu_usage']:.1f}%",
                'value': latest_data['cpu_usage'],
                'metric': 'cpu_usage'
            })
        elif latest_data.get('cpu_usage', 0) > self.alert_rules['cpu_high']['threshold']:
            alerts.append({
                'timestamp': current_time,
                'node': node_name,
                'severity': 'warning',
                'message': f"High CPU usage: {latest_data['cpu_usage']:.1f}%",
                'value': latest_data['cpu_usage'],
                'metric': 'cpu_usage'
            })
        
        # Check memory alerts
        if latest_data.get('memory_usage', 0) > self.alert_rules['memory_critical']['threshold']:
            alerts.append({
                'timestamp': current_time,
                'node': node_name,
                'severity': 'critical',
                'message': f"Critical memory usage: {latest_data['memory_usage']:.1f}%",
                'value': latest_data['memory_usage'],
                'metric': 'memory_usage'
            })
        elif latest_data.get('memory_usage', 0) > self.alert_rules['memory_high']['threshold']:
            alerts.append({
                'timestamp': current_time,
                'node': node_name,
                'severity': 'warning',
                'message': f"High memory usage: {latest_data['memory_usage']:.1f}%",
                'value': latest_data['memory_usage'],
                'metric': 'memory_usage'
            })
        
        # Check buffer cache hit ratio
        if latest_data.get('buffer_cache_hit_ratio', 100) < self.alert_rules['buffer_cache_low']['threshold']:
            alerts.append({
                'timestamp': current_time,
                'node': node_name,
                'severity': 'warning',
                'message': f"Low buffer cache hit ratio: {latest_data['buffer_cache_hit_ratio']:.1f}%",
                'value': latest_data['buffer_cache_hit_ratio'],
                'metric': 'buffer_cache_hit_ratio'
            })
        
        # Check page life expectancy
        if latest_data.get('page_life_expectancy', 3000) < self.alert_rules['page_life_low']['threshold']:
            alerts.append({
                'timestamp': current_time,
                'node': node_name,
                'severity': 'critical',
                'message': f"Low page life expectancy: {latest_data['page_life_expectancy']:.0f}s",
                'value': latest_data['page_life_expectancy'],
                'metric': 'page_life_expectancy'
            })
        
        return alerts
    
    def add_alerts(self, alerts: List[Dict]):
        """Add new alerts to session state"""
        st.session_state.alerts.extend(alerts)
        # Keep only last 100 alerts
        st.session_state.alerts = st.session_state.alerts[-100:]
    
    def get_recent_alerts(self, hours: int = 24) -> List[Dict]:
        """Get recent alerts within specified hours"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        return [alert for alert in st.session_state.alerts 
                if alert['timestamp'] > cutoff_time]

# =================== Autonomous Recovery System ===================
class AutonomousRecovery:
    def __init__(self, aws_connector: AWSCloudWatchConnector):
        self.aws_connector = aws_connector
        self.recovery_actions = {
            'high_cpu': self.restart_sql_service,
            'high_memory': self.clear_buffer_cache,
            'connection_limit': self.kill_idle_connections,
            'disk_space': self.shrink_log_files,
            'failover_required': self.initiate_failover
        }
    
    def analyze_and_recover(self, alerts: List[Dict], node_name: str) -> List[str]:
        """Analyze alerts and suggest/execute recovery actions"""
        recovery_actions = []
        
        for alert in alerts:
            if alert['severity'] == 'critical':
                if alert['metric'] == 'cpu_usage' and alert['value'] > 95:
                    action = f"Suggested: Restart SQL Server service on {node_name}"
                    recovery_actions.append(action)
                
                elif alert['metric'] == 'memory_usage' and alert['value'] > 95:
                    action = f"Suggested: Clear buffer cache on {node_name}"
                    recovery_actions.append(action)
                
                elif alert['metric'] == 'page_life_expectancy' and alert['value'] < 300:
                    action = f"Suggested: Investigate memory pressure on {node_name}"
                    recovery_actions.append(action)
        
        return recovery_actions
    
    def restart_sql_service(self, node_name: str) -> bool:
        """Restart SQL Server service (mock implementation)"""
        # In real implementation, use AWS Systems Manager or PowerShell
        st.info(f"🔄 Restarting SQL Server service on {node_name}")
        return True
    
    def clear_buffer_cache(self, node_name: str) -> bool:
        """Clear SQL Server buffer cache (mock implementation)"""
        st.info(f"🗑️ Clearing buffer cache on {node_name}")
        return True
    
    def kill_idle_connections(self, node_name: str) -> bool:
        """Kill idle connections (mock implementation)"""
        st.info(f"🔌 Killing idle connections on {node_name}")
        return True
    
    def shrink_log_files(self, node_name: str) -> bool:
        """Shrink transaction log files (mock implementation)"""
        st.info(f"📦 Shrinking log files on {node_name}")
        return True
    
    def initiate_failover(self, from_node: str, to_node: str) -> bool:
        """Initiate Always On failover (mock implementation)"""
        st.warning(f"⚠️ Initiating failover from {from_node} to {to_node}")
        return True

# =================== Main Application ===================
def main():
    st.title("🔍 SQL Server AI Monitoring & Predictive Analytics")
    st.markdown("**Real-time monitoring, fault detection, and autonomous recovery for SQL Server Always On clusters**")
    
    # Initialize session state
    if 'ml_predictor' not in st.session_state:
        st.session_state.ml_predictor = SQLServerMLPredictor()
    
    if 'alert_manager' not in st.session_state:
        st.session_state.alert_manager = AlertManager()
    
    if 'data_generator' not in st.session_state:
        st.session_state.data_generator = DataGenerator()
    
    # Sidebar configuration
    with st.sidebar:
        st.header("⚙️ Configuration")
        
        # AWS Configuration
        st.subheader("AWS Settings")
        aws_access_key = st.text_input("AWS Access Key", type="password", value="demo_key")
        aws_secret_key = st.text_input("AWS Secret Key", type="password", value="demo_secret")
        aws_region = st.selectbox("AWS Region", ["us-east-1", "us-west-2", "eu-west-1"], index=0)
        
        # Cluster Configuration
        st.subheader("Cluster Settings")
        node_count = st.slider("Number of Nodes", 2, 5, 3)
        refresh_interval = st.slider("Refresh Interval (seconds)", 5, 60, 30)
        
        # ML Configuration
        st.subheader("ML Settings")
        enable_auto_training = st.checkbox("Auto-train ML models", value=True)
        enable_autonomous_recovery = st.checkbox("Enable autonomous recovery", value=False)
        
        st.markdown("---")
        st.markdown("**Data Source**: Demo mode using synthetic data")
        st.markdown("**Status**: ✅ Connected")
    
    # Initialize AWS connector (demo mode)
    try:
        aws_connector = AWSCloudWatchConnector(aws_access_key, aws_secret_key, aws_region)
        recovery_system = AutonomousRecovery(aws_connector)
    except:
        st.warning("Using demo mode - AWS connector not available")
        aws_connector = None
        recovery_system = None
    
    # Main tabs
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "🏠 Dashboard", 
        "🔮 Predictions", 
        "🚨 Alerts", 
        "🔧 Maintenance",
        "📊 Analytics"
    ])
    
    # Generate real-time data
    nodes_data = st.session_state.data_generator.generate_realtime_metrics(node_count)
    
    # Train ML models if enabled
    if enable_auto_training and not st.session_state.ml_predictor.is_trained:
        with st.spinner("Training ML models..."):
            historical_data = st.session_state.data_generator.generate_historical_data()
            st.session_state.ml_predictor.train_models(historical_data)
    
    # =================== Dashboard Tab ===================
    with tab1:
        st.header("📊 Real-time Dashboard")
        
        # Key metrics overview
        col1, col2, col3, col4 = st.columns(4)
        
        # Calculate cluster-wide metrics
        total_cpu = np.mean([data['cpu_usage'].iloc[-1] for data in nodes_data.values()])
        total_memory = np.mean([data['memory_usage'].iloc[-1] for data in nodes_data.values()])
        total_connections = sum([data['connections'].iloc[-1] for data in nodes_data.values()])
        avg_buffer_cache = np.mean([data['buffer_cache_hit_ratio'].iloc[-1] for data in nodes_data.values()])
        
        with col1:
            st.metric("Cluster CPU Usage", f"{total_cpu:.1f}%", 
                     delta=f"{np.random.uniform(-2, 2):.1f}%")
        
        with col2:
            st.metric("Cluster Memory Usage", f"{total_memory:.1f}%", 
                     delta=f"{np.random.uniform(-1, 3):.1f}%")
        
        with col3:
            st.metric("Total Connections", f"{total_connections:.0f}", 
                     delta=f"{np.random.randint(-5, 10)}")
        
        with col4:
            st.metric("Avg Buffer Cache Hit Ratio", f"{avg_buffer_cache:.1f}%", 
                     delta=f"{np.random.uniform(-0.5, 0.5):.2f}%")
        
        st.markdown("---")
        
        # Per-node monitoring
        for node_name, node_data in nodes_data.items():
            with st.expander(f"📈 {node_name} Metrics", expanded=True):
                
                # Node status indicators
                col1, col2, col3 = st.columns(3)
                with col1:
                    cpu_val = node_data['cpu_usage'].iloc[-1]
                    cpu_color = "🔴" if cpu_val > 80 else "🟡" if cpu_val > 60 else "🟢"
                    st.metric(f"CPU Usage {cpu_color}", f"{cpu_val:.1f}%")
                
                with col2:
                    mem_val = node_data['memory_usage'].iloc[-1]
                    mem_color = "🔴" if mem_val > 85 else "🟡" if mem_val > 70 else "🟢"
                    st.metric(f"Memory Usage {mem_color}", f"{mem_val:.1f}%")
                
                with col3:
                    conn_val = node_data['connections'].iloc[-1]
                    conn_color = "🔴" if conn_val > 150 else "🟡" if conn_val > 100 else "🟢"
                    st.metric(f"Connections {conn_color}", f"{conn_val:.0f}")
                
                # Real-time charts
                fig = make_subplots(
                    rows=2, cols=2,
                    subplot_titles=('CPU & Memory Usage', 'Connections', 'Buffer Cache Hit Ratio', 'Page Life Expectancy'),
                    specs=[[{"secondary_y": True}, {"secondary_y": False}],
                           [{"secondary_y": False}, {"secondary_y": False}]]
                )
                
                # CPU and Memory
                fig.add_trace(
                    go.Scatter(x=node_data['timestamp'], y=node_data['cpu_usage'], 
                              name='CPU %', line=dict(color='red')),
                    row=1, col=1
                )
                fig.add_trace(
                    go.Scatter(x=node_data['timestamp'], y=node_data['memory_usage'], 
                              name='Memory %', line=dict(color='blue')),
                    row=1, col=1, secondary_y=True
                )
                
                # Connections
                fig.add_trace(
                    go.Scatter(x=node_data['timestamp'], y=node_data['connections'], 
                              name='Connections', line=dict(color='green')),
                    row=1, col=2
                )
                
                # Buffer Cache Hit Ratio
                fig.add_trace(
                    go.Scatter(x=node_data['timestamp'], y=node_data['buffer_cache_hit_ratio'], 
                              name='Buffer Cache %', line=dict(color='orange')),
                    row=2, col=1
                )
                
                # Page Life Expectancy
                fig.add_trace(
                    go.Scatter(x=node_data['timestamp'], y=node_data['page_life_expectancy'], 
                              name='Page Life Exp', line=dict(color='purple')),
                    row=2, col=2
                )
                
                fig.update_layout(height=400, showlegend=False)
                st.plotly_chart(fig, use_container_width=True)
                
                # Evaluate alerts for this node
                node_alerts = st.session_state.alert_manager.evaluate_alerts(node_data, node_name)
                if node_alerts:
                    st.session_state.alert_manager.add_alerts(node_alerts)
                    
                    # Display immediate alerts
                    for alert in node_alerts:
                        if alert['severity'] == 'critical':
                            st.error(f"🚨 {alert['message']}")
                        else:
                            st.warning(f"⚠️ {alert['message']}")
                    
                    # Autonomous recovery
                    if enable_autonomous_recovery and recovery_system:
                        recovery_actions = recovery_system.analyze_and_recover(node_alerts, node_name)
                        if recovery_actions:
                            st.info("🤖 Autonomous Recovery Actions:")
                            for action in recovery_actions:
                                st.write(f"• {action}")
    
    # =================== Predictions Tab ===================
    with tab2:
        st.header("🔮 Predictive Analytics")
        
        if st.session_state.ml_predictor.is_trained:
            
            # Anomaly Detection
            st.subheader("🕵️ Anomaly Detection")
            
            anomaly_results = {}
            for node_name, node_data in nodes_data.items():
                anomaly_result = st.session_state.ml_predictor.predict_anomaly(node_data)
                anomaly_results[node_name] = anomaly_result
            
            # Display anomaly results
            cols = st.columns(len(nodes_data))
            for i, (node_name, result) in enumerate(anomaly_results.items()):
                with cols[i]:
                    if result['is_anomaly']:
                        st.error(f"🚨 {node_name}")
                        st.write("**Status:** Anomaly Detected")
                        st.write(f"**Confidence:** {result['confidence']:.1f}%")
                    else:
                        st.success(f"✅ {node_name}")
                        st.write("**Status:** Normal")
                        st.write(f"**Confidence:** {100 - result['confidence']:.1f}%")
            
            st.markdown("---")
            
            # Failure Prediction
            st.subheader("⚠️ Failure Prediction (24-hour outlook)")
            
            failure_results = {}
            for node_name, node_data in nodes_data.items():
                failure_result = st.session_state.ml_predictor.predict_failure(node_data)
                failure_results[node_name] = failure_result
            
            # Create failure probability chart
            fig = go.Figure()
            
            node_names = list(failure_results.keys())
            failure_probs = [result['failure_probability'] for result in failure_results.values()]
            risk_levels = [result['risk_level'] for result in failure_results.values()]
            
            colors = ['red' if level == 'Critical' else 'orange' if level == 'High' else 
                     'yellow' if level == 'Medium' else 'green' for level in risk_levels]
            
            fig.add_trace(go.Bar(
                x=node_names,
                y=failure_probs,
                marker_color=colors,
                text=[f"{prob:.1f}%<br>{level}" for prob, level in zip(failure_probs, risk_levels)],
                textposition='auto'
            ))
            
            fig.update_layout(
                title="Failure Probability by Node (Next 24 Hours)",
                xaxis_title="Nodes",
                yaxis_title="Failure Probability (%)",
                height=400
            )
            
            st.plotly_chart(fig, use_container_width=True)
            
            # Detailed predictions
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("📈 Performance Trends")
                
                # Predict future resource usage
                for node_name, node_data in nodes_data.items():
                    current_cpu = node_data['cpu_usage'].iloc[-1]
                    current_memory = node_data['memory_usage'].iloc[-1]
                    
                    # Simple trend prediction
                    cpu_trend = np.polyfit(range(len(node_data)), node_data['cpu_usage'], 1)[0]
                    memory_trend = np.polyfit(range(len(node_data)), node_data['memory_usage'], 1)[0]
                    
                    predicted_cpu = current_cpu + (cpu_trend * 60)  # 1 hour ahead
                    predicted_memory = current_memory + (memory_trend * 60)
                    
                    st.write(f"**{node_name}:**")
                    st.write(f"CPU (1h): {current_cpu:.1f}% → {predicted_cpu:.1f}% "
                            f"({'📈' if cpu_trend > 0 else '📉'})")
                    st.write(f"Memory (1h): {current_memory:.1f}% → {predicted_memory:.1f}% "
                            f"({'📈' if memory_trend > 0 else '📉'})")
                    st.write("---")
            
            with col2:
                st.subheader("🎯 Recommendations")
                
                # Generate recommendations based on predictions
                recommendations = []
                
                for node_name, result in failure_results.items():
                    if result['risk_level'] == 'Critical':
                        recommendations.append(f"🚨 **{node_name}**: Immediate attention required")
                        recommendations.append(f"   • Schedule emergency maintenance")
                        recommendations.append(f"   • Consider failover to secondary node")
                    elif result['risk_level'] == 'High':
                        recommendations.append(f"⚠️ **{node_name}**: Monitor closely")
                        recommendations.append(f"   • Schedule maintenance within 24 hours")
                        recommendations.append(f"   • Review resource allocation")
                    elif result['risk_level'] == 'Medium':
                        recommendations.append(f"📊 **{node_name}**: Schedule routine maintenance")
                
                if not recommendations:
                    recommendations.append("✅ All nodes operating within normal parameters")
                
                for rec in recommendations:
                    st.write(rec)
        
        else:
            st.info("🤖 ML models are training... Please wait or enable auto-training in the sidebar.")
            if st.button("Train Models Now"):
                with st.spinner("Training ML models..."):
                    historical_data = st.session_state.data_generator.generate_historical_data()
                    st.session_state.ml_predictor.train_models(historical_data)
                    st.rerun()
    
    # =================== Alerts Tab ===================
    with tab3:
        st.header("🚨 Alert Management")
        
        # Recent alerts summary
        recent_alerts = st.session_state.alert_manager.get_recent_alerts()
        
        col1, col2, col3 = st.columns(3)
        with col1:
            critical_count = len([a for a in recent_alerts if a['severity'] == 'critical'])
            st.metric("Critical Alerts (24h)", critical_count)
        
        with col2:
            warning_count = len([a for a in recent_alerts if a['severity'] == 'warning'])
            st.metric("Warning Alerts (24h)", warning_count)
        
        with col3:
            total_count = len(recent_alerts)
            st.metric("Total Alerts (24h)", total_count)
        
        st.markdown("---")
        
        # Alert timeline
        if recent_alerts:
            st.subheader("📈 Alert Timeline")
            
            # Convert alerts to DataFrame for plotting
            alert_df = pd.DataFrame(recent_alerts)
            alert_df['timestamp'] = pd.to_datetime(alert_df['timestamp'])
            
            # Group alerts by hour
            alert_df['hour'] = alert_df['timestamp'].dt.floor('H')
            hourly_alerts = alert_df.groupby(['hour', 'severity']).size().reset_index(name='count')
            
            fig = px.bar(hourly_alerts, x='hour', y='count', color='severity',
                        title="Alerts by Hour and Severity",
                        color_discrete_map={'critical': 'red', 'warning': 'orange', 'info': 'blue'})
            
            st.plotly_chart(fig, use_container_width=True)
            
            st.markdown("---")
            
            # Recent alerts list
            st.subheader("📋 Recent Alerts")
            
            # Filter options
            col1, col2 = st.columns(2)
            with col1:
                severity_filter = st.selectbox("Filter by Severity", 
                                             ["All", "critical", "warning", "info"])
            with col2:
                time_filter = st.selectbox("Time Range", 
                                         ["Last 1 hour", "Last 6 hours", "Last 24 hours"])
            
            # Apply filters
            filtered_alerts = recent_alerts.copy()
            
            if severity_filter != "All":
                filtered_alerts = [a for a in filtered_alerts if a['severity'] == severity_filter]
            
            time_ranges = {"Last 1 hour": 1, "Last 6 hours": 6, "Last 24 hours": 24}
            cutoff = datetime.now() - timedelta(hours=time_ranges[time_filter])
            filtered_alerts = [a for a in filtered_alerts if a['timestamp'] > cutoff]
            
            # Display alerts
            for alert in sorted(filtered_alerts, key=lambda x: x['timestamp'], reverse=True)[:20]:
                severity_class = f"alert-{alert['severity']}"
                timestamp_str = alert['timestamp'].strftime("%Y-%m-%d %H:%M:%S")
                
                if alert['severity'] == 'critical':
                    st.error(f"🚨 **{alert['node']}** - {alert['message']} ({timestamp_str})")
                elif alert['severity'] == 'warning':
                    st.warning(f"⚠️ **{alert['node']}** - {alert['message']} ({timestamp_str})")
                else:
                    st.info(f"ℹ️ **{alert['node']}** - {alert['message']} ({timestamp_str})")
        
        else:
            st.success("🎉 No recent alerts! All systems are running smoothly.")
        
        # Alert configuration
        st.markdown("---")
        st.subheader("⚙️ Alert Configuration")
        
        with st.expander("Alert Thresholds"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.write("**Resource Thresholds**")
                cpu_warning = st.slider("CPU Warning (%)", 0, 100, 80)
                cpu_critical = st.slider("CPU Critical (%)", 0, 100, 95)
                memory_warning = st.slider("Memory Warning (%)", 0, 100, 85)
                memory_critical = st.slider("Memory Critical (%)", 0, 100, 95)
            
            with col2:
                st.write("**SQL Server Thresholds**")
                buffer_cache_warning = st.slider("Buffer Cache Warning (%)", 0, 100, 90)
                page_life_critical = st.slider("Page Life Critical (sec)", 0, 1000, 300)
                connection_warning = st.slider("Connection Warning", 0, 500, 200)
            
            if st.button("Update Alert Thresholds"):
                # Update alert manager thresholds
                st.session_state.alert_manager.alert_rules.update({
                    'cpu_high': {'threshold': cpu_warning, 'severity': 'warning'},
                    'cpu_critical': {'threshold': cpu_critical, 'severity': 'critical'},
                    'memory_high': {'threshold': memory_warning, 'severity': 'warning'},
                    'memory_critical': {'threshold': memory_critical, 'severity': 'critical'},
                    'buffer_cache_low': {'threshold': buffer_cache_warning, 'severity': 'warning'},
                    'page_life_low': {'threshold': page_life_critical, 'severity': 'critical'},
                    'connections_high': {'threshold': connection_warning, 'severity': 'warning'}
                })
                st.success("Alert thresholds updated!")
    
    # =================== Maintenance Tab ===================
    with tab4:
        st.header("🔧 Proactive Maintenance")
        
        # Maintenance recommendations
        st.subheader("📋 Maintenance Recommendations")
        
        # Analyze current state and generate recommendations
        maintenance_tasks = []
        
        for node_name, node_data in nodes_data.items():
            latest_data = node_data.iloc[-1]
            
            # Check various maintenance conditions
            if latest_data['buffer_cache_hit_ratio'] < 95:
                maintenance_tasks.append({
                    'priority': 'Medium',
                    'node': node_name,
                    'task': 'Optimize buffer cache',
                    'description': f"Buffer cache hit ratio is {latest_data['buffer_cache_hit_ratio']:.1f}%. Consider reviewing memory allocation.",
                    'estimated_time': '30 minutes',
                    'impact': 'Low'
                })
            
            if latest_data['page_life_expectancy'] < 1000:
                maintenance_tasks.append({
                    'priority': 'High',
                    'node': node_name,
                    'task': 'Investigate memory pressure',
                    'description': f"Page life expectancy is {latest_data['page_life_expectancy']:.0f}s. Memory pressure detected.",
                    'estimated_time': '1 hour',
                    'impact': 'Medium'
                })
            
            if latest_data['log_growth_rate'] > 20:
                maintenance_tasks.append({
                    'priority': 'Medium',
                    'node': node_name,
                    'task': 'Log file maintenance',
                    'description': f"Transaction log growth rate is high ({latest_data['log_growth_rate']:.1f} MB/min).",
                    'estimated_time': '45 minutes',
                    'impact': 'Low'
                })
            
            # Weekly maintenance tasks
            maintenance_tasks.extend([
                {
                    'priority': 'Low',
                    'node': node_name,
                    'task': 'Index maintenance',
                    'description': 'Rebuild fragmented indexes and update statistics',
                    'estimated_time': '2 hours',
                    'impact': 'Medium'
                },
                {
                    'priority': 'Low',
                    'node': node_name,
                    'task': 'Backup verification',
                    'description': 'Verify backup integrity and restore procedures',
                    'estimated_time': '1 hour',
                    'impact': 'Low'
                }
            ])
        
        # Sort by priority
        priority_order = {'High': 1, 'Medium': 2, 'Low': 3}
        maintenance_tasks.sort(key=lambda x: priority_order[x['priority']])
        
        # Display maintenance tasks
        for task in maintenance_tasks[:10]:  # Show top 10 tasks
            priority_color = {'High': '🔴', 'Medium': '🟡', 'Low': '🟢'}[task['priority']]
            
            with st.expander(f"{priority_color} {task['priority']} - {task['task']} ({task['node']})"):
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.write(f"**Estimated Time:** {task['estimated_time']}")
                
                with col2:
                    st.write(f"**Impact:** {task['impact']}")
                
                with col3:
                    if st.button(f"Schedule", key=f"schedule_{task['node']}_{task['task']}"):
                        st.success(f"Maintenance scheduled for {task['node']}")
                
                st.write(f"**Description:** {task['description']}")
        
        st.markdown("---")
        
        # Maintenance calendar
        st.subheader("📅 Maintenance Calendar")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Upcoming Scheduled Maintenance:**")
            
            # Mock scheduled maintenance
            scheduled_maintenance = [
                {"date": "2025-06-23", "task": "Index Rebuild - Node_1", "time": "02:00 AM"},
                {"date": "2025-06-24", "task": "Statistics Update - All Nodes", "time": "01:00 AM"},
                {"date": "2025-06-25", "task": "Log Backup Verification", "time": "03:00 AM"},
                {"date": "2025-06-30", "task": "Monthly Health Check", "time": "02:00 AM"}
            ]
            
            for maintenance in scheduled_maintenance:
                st.write(f"📅 **{maintenance['date']}** at {maintenance['time']}")
                st.write(f"   {maintenance['task']}")
                st.write("---")
        
        with col2:
            st.write("**Maintenance History:**")
            
            # Mock maintenance history
            maintenance_history = [
                {"date": "2025-06-20", "task": "Emergency failover test", "status": "Completed", "duration": "45 min"},
                {"date": "2025-06-18", "task": "Buffer cache optimization", "status": "Completed", "duration": "30 min"},
                {"date": "2025-06-15", "task": "Index maintenance", "status": "Completed", "duration": "2h 15min"},
                {"date": "2025-06-12", "task": "Security patches", "status": "Completed", "duration": "1h 30min"}
            ]
            
            for history in maintenance_history:
                status_icon = "✅" if history['status'] == 'Completed' else "⏳"
                st.write(f"{status_icon} **{history['date']}** ({history['duration']})")
                st.write(f"   {history['task']}")
                st.write("---")
        
        # Capacity planning
        st.markdown("---")
        st.subheader("📊 Capacity Planning")
        
        # Generate capacity forecasts
        forecast_data = []
        for node_name, node_data in nodes_data.items():
            # Simple linear extrapolation for demo
            cpu_trend = np.polyfit(range(len(node_data)), node_data['cpu_usage'], 1)[0]
            memory_trend = np.polyfit(range(len(node_data)), node_data['memory_usage'], 1)[0]
            
            current_cpu = node_data['cpu_usage'].iloc[-1]
            current_memory = node_data['memory_usage'].iloc[-1]
            
            # Forecast 30, 60, 90 days
            for days in [30, 60, 90]:
                forecast_cpu = current_cpu + (cpu_trend * days * 24)  # Daily trend
                forecast_memory = current_memory + (memory_trend * days * 24)
                
                forecast_data.append({
                    'Node': node_name,
                    'Days': days,
                    'CPU_Forecast': max(0, min(100, forecast_cpu)),
                    'Memory_Forecast': max(0, min(100, forecast_memory))
                })
        
        forecast_df = pd.DataFrame(forecast_data)
        
        # Capacity forecast chart
        fig = make_subplots(
            rows=1, cols=2,
            subplot_titles=('CPU Usage Forecast', 'Memory Usage Forecast')
        )
        
        for node in forecast_df['Node'].unique():
            node_forecast = forecast_df[forecast_df['Node'] == node]
            
            fig.add_trace(
                go.Scatter(x=node_forecast['Days'], y=node_forecast['CPU_Forecast'],
                          name=f'{node} CPU', mode='lines+markers'),
                row=1, col=1
            )
            
            fig.add_trace(
                go.Scatter(x=node_forecast['Days'], y=node_forecast['Memory_Forecast'],
                          name=f'{node} Memory', mode='lines+markers'),
                row=1, col=2
            )
        
        # Add capacity thresholds
        fig.add_hline(y=80, line_dash="dash", line_color="orange", 
                     annotation_text="Warning Threshold", row=1, col=1)
        fig.add_hline(y=80, line_dash="dash", line_color="orange", row=1, col=2)
        
        fig.update_layout(height=400, title_text="Resource Usage Forecast")
        st.plotly_chart(fig, use_container_width=True)
        
        # Capacity recommendations
        st.subheader("💡 Capacity Recommendations")
        
        capacity_alerts = []
        for _, row in forecast_df.iterrows():
            if row['CPU_Forecast'] > 80:
                capacity_alerts.append(
                    f"⚠️ **{row['Node']}**: CPU usage may exceed 80% in {row['Days']} days"
                )
            if row['Memory_Forecast'] > 80:
                capacity_alerts.append(
                    f"⚠️ **{row['Node']}**: Memory usage may exceed 80% in {row['Days']} days"
                )
        
        if capacity_alerts:
            for alert in capacity_alerts[:5]:  # Show top 5
                st.warning(alert)
        else:
            st.success("✅ No capacity concerns identified in the next 90 days")
    
    # =================== Analytics Tab ===================
    with tab5:
        st.header("📊 Historical Analytics")
        
        # Generate historical data for analysis
        historical_data = st.session_state.data_generator.generate_historical_data(30)
        
        # Time range selector
        col1, col2 = st.columns(2)
        with col1:
            start_date = st.date_input("Start Date", 
                                     value=datetime.now().date() - timedelta(days=7))
        with col2:
            end_date = st.date_input("End Date", 
                                   value=datetime.now().date())
        
        # Filter data by date range
        start_datetime = datetime.combine(start_date, datetime.min.time())
        end_datetime = datetime.combine(end_date, datetime.max.time())
        
        filtered_data = historical_data[
            (historical_data['timestamp'] >= start_datetime) & 
            (historical_data['timestamp'] <= end_datetime)
        ]
        
        if filtered_data.empty:
            st.warning("No data available for the selected date range")
            return
        
        # Performance trends
        st.subheader("📈 Performance Trends")
        
        # Resample data for better visualization
        filtered_data.set_index('timestamp', inplace=True)
        daily_stats = filtered_data.resample('D').agg({
            'cpu_usage': ['mean', 'max'],
            'memory_usage': ['mean', 'max'],
            'connections': ['mean', 'max'],
            'buffer_cache_hit_ratio': 'mean',
            'page_life_expectancy': 'mean'
        }).reset_index()
        
        # Flatten column names
        daily_stats.columns = ['timestamp'] + [f"{col[0]}_{col[1]}" if col[1] else col[0] 
                                              for col in daily_stats.columns[1:]]
        
        # Create trend charts
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=('CPU Usage Trends', 'Memory Usage Trends', 
                          'Connection Trends', 'Buffer Cache Performance'),
            specs=[[{"secondary_y": True}, {"secondary_y": True}],
                   [{"secondary_y": False}, {"secondary_y": False}]]
        )
        
        # CPU trends
        fig.add_trace(
            go.Scatter(x=daily_stats['timestamp'], y=daily_stats['cpu_usage_mean'],
                      name='CPU Avg', line=dict(color='blue')),
            row=1, col=1
        )
        fig.add_trace(
            go.Scatter(x=daily_stats['timestamp'], y=daily_stats['cpu_usage_max'],
                      name='CPU Max', line=dict(color='red', dash='dash')),
            row=1, col=1, secondary_y=True
        )
        
        # Memory trends
        fig.add_trace(
            go.Scatter(x=daily_stats['timestamp'], y=daily_stats['memory_usage_mean'],
                      name='Memory Avg', line=dict(color='green')),
            row=1, col=2
        )
        fig.add_trace(
            go.Scatter(x=daily_stats['timestamp'], y=daily_stats['memory_usage_max'],
                      name='Memory Max', line=dict(color='orange', dash='dash')),
            row=1, col=2, secondary_y=True
        )
        
        # Connection trends
        fig.add_trace(
            go.Scatter(x=daily_stats['timestamp'], y=daily_stats['connections_mean'],
                      name='Connections Avg', line=dict(color='purple')),
            row=2, col=1
        )
        
        # Buffer cache trends
        fig.add_trace(
            go.Scatter(x=daily_stats['timestamp'], y=daily_stats['buffer_cache_hit_ratio_mean'],
                      name='Buffer Cache %', line=dict(color='brown')),
            row=2, col=2
        )
        
        fig.update_layout(height=600, showlegend=False)
        st.plotly_chart(fig, use_container_width=True)
        
        st.markdown("---")
        
        # Performance summary statistics
        st.subheader("📋 Performance Summary")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Avg CPU Usage", f"{filtered_data['cpu_usage'].mean():.1f}%",
                     delta=f"{filtered_data['cpu_usage'].std():.1f}% std")
            st.metric("Max CPU Usage", f"{filtered_data['cpu_usage'].max():.1f}%")
        
        with col2:
            st.metric("Avg Memory Usage", f"{filtered_data['memory_usage'].mean():.1f}%",
                     delta=f"{filtered_data['memory_usage'].std():.1f}% std")
            st.metric("Max Memory Usage", f"{filtered_data['memory_usage'].max():.1f}%")
        
        with col3:
            st.metric("Avg Connections", f"{filtered_data['connections'].mean():.0f}",
                     delta=f"{filtered_data['connections'].std():.0f} std")
            st.metric("Max Connections", f"{filtered_data['connections'].max():.0f}")
        
        with col4:
            st.metric("Avg Buffer Cache", f"{filtered_data['buffer_cache_hit_ratio'].mean():.2f}%")
            st.metric("Min Buffer Cache", f"{filtered_data['buffer_cache_hit_ratio'].min():.2f}%")
        
        # Pattern analysis
        st.markdown("---")
        st.subheader("🔍 Pattern Analysis")
        
        # Hourly patterns
        filtered_data['hour'] = filtered_data.index.hour
        filtered_data['day_of_week'] = filtered_data.index.dayofweek
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Hourly CPU pattern
            hourly_cpu = filtered_data.groupby('hour')['cpu_usage'].mean()
            
            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=hourly_cpu.index,
                y=hourly_cpu.values,
                mode='lines+markers',
                name='Hourly CPU Pattern',
                line=dict(color='blue', width=3)
            ))
            
            fig.update_layout(
                title="Average CPU Usage by Hour",
                xaxis_title="Hour of Day",
                yaxis_title="CPU Usage (%)",
                height=300
            )
            
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Daily pattern
            day_names = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
            daily_cpu = filtered_data.groupby('day_of_week')['cpu_usage'].mean()
            
            fig = go.Figure()
            fig.add_trace(go.Bar(
                x=[day_names[i] for i in daily_cpu.index],
                y=daily_cpu.values,
                marker_color='lightblue',
                name='Daily CPU Pattern'
            ))
            
            fig.update_layout(
                title="Average CPU Usage by Day of Week",
                xaxis_title="Day of Week",
                yaxis_title="CPU Usage (%)",
                height=300
            )
            
            st.plotly_chart(fig, use_container_width=True)
        
        # Correlation analysis
        st.markdown("---")
        st.subheader("🔗 Correlation Analysis")
        
        # Calculate correlations
        correlation_metrics = ['cpu_usage', 'memory_usage', 'connections', 
                             'buffer_cache_hit_ratio', 'page_life_expectancy']
        
        available_metrics = [metric for metric in correlation_metrics 
                           if metric in filtered_data.columns]
        
        if len(available_metrics) > 1:
            correlation_matrix = filtered_data[available_metrics].corr()
            
            fig = go.Figure(data=go.Heatmap(
                z=correlation_matrix.values,
                x=correlation_matrix.columns,
                y=correlation_matrix.columns,
                colorscale='RdBu',
                zmid=0,
                text=correlation_matrix.round(2).values,
                texttemplate="%{text}",
                textfont={"size": 12},
                hoverongaps=False
            ))
            
            fig.update_layout(
                title="Metric Correlation Matrix",
                height=400
            )
            
            st.plotly_chart(fig, use_container_width=True)
            
            # Insights from correlation
            st.subheader("💡 Correlation Insights")
            
            insights = []
            
            # Check for high correlations
            for i in range(len(correlation_matrix.columns)):
                for j in range(i+1, len(correlation_matrix.columns)):
                    corr_value = correlation_matrix.iloc[i, j]
                    metric1 = correlation_matrix.columns[i]
                    metric2 = correlation_matrix.columns[j]
                    
                    if abs(corr_value) > 0.7:
                        relationship = "positively" if corr_value > 0 else "negatively"
                        insights.append(
                            f"**{metric1}** and **{metric2}** are strongly {relationship} "
                            f"correlated (r={corr_value:.2f})"
                        )
            
            if insights:
                for insight in insights:
                    st.write(f"• {insight}")
            else:
                st.write("• No strong correlations detected between metrics")
    
    # Auto-refresh functionality
    if 'last_refresh' not in st.session_state:
        st.session_state.last_refresh = datetime.now()
    
    time_since_refresh = (datetime.now() - st.session_state.last_refresh).seconds
    
    if time_since_refresh >= refresh_interval:
        st.session_state.last_refresh = datetime.now()
        st.rerun()
    
    # Display refresh status
    st.sidebar.markdown("---")
    st.sidebar.write(f"🔄 Last refresh: {st.session_state.last_refresh.strftime('%H:%M:%S')}")
    st.sidebar.write(f"⏱️ Next refresh in: {refresh_interval - time_since_refresh}s")
    
    if st.sidebar.button("🔄 Refresh Now"):
        st.rerun()

if __name__ == "__main__":
    main()