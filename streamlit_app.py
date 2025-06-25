# Enhanced StreamlitAWSManager with better debugging
class StreamlitAWSManager:
    """Enhanced AWS connection manager with detailed debugging"""
    
    def __init__(self):
        self.is_streamlit_cloud = self._detect_streamlit_cloud()
        self.demo_mode = not AWS_AVAILABLE
        self.debug_info = []  # Store debug information
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
            'user_arn': None,
            'debug_info': []
        }
        self.aws_session = None
        self.clients = {}
    
    def initialize_aws_connection(self, aws_config: Dict) -> bool:
        """Initialize AWS connection with enhanced debugging"""
        self.debug_info = []
        
        if not AWS_AVAILABLE:
            self.demo_mode = True
            self.debug_info.append("❌ boto3 not available - running in demo mode")
            self.connection_status['error'] = "boto3 not available - running in demo mode"
            self.connection_status['debug_info'] = self.debug_info
            return True
        
        self.debug_info.append("✅ boto3 is available")
        self._reset_connection_state()
        
        # Extract and clean configuration
        access_key = str(aws_config.get('access_key', '')).strip()
        secret_key = str(aws_config.get('secret_key', '')).strip()
        region = str(aws_config.get('region', 'us-east-1')).strip()
        
        self.debug_info.append(f"🌍 Target region: {region}")
        
        # Set region in environment for boto3
        os.environ['AWS_DEFAULT_REGION'] = region
        
        # Try multiple credential methods in order of preference
        connection_methods = [
            ('environment_variables', self._try_environment_credentials, (region,)),
            ('explicit_credentials', self._try_explicit_credentials, (access_key, secret_key, region)),
            ('shared_credentials', self._try_shared_credentials, (region,)),
            ('instance_metadata', self._try_instance_metadata, (region,))
        ]
        
        for method_name, method_func, args in connection_methods:
            try:
                self.debug_info.append(f"🔄 Attempting {method_name}")
                logger.info(f"Attempting AWS connection via {method_name}")
                
                session = method_func(*args)
                if session:
                    self.debug_info.append(f"✅ {method_name} session created")
                    if self._test_session(session, method_name):
                        self.aws_session = session
                        self._initialize_clients()
                        self.connection_status['method'] = method_name
                        self.connection_status['connected'] = True
                        self.connection_status['debug_info'] = self.debug_info
                        self.demo_mode = False
                        self.debug_info.append(f"🎉 Successfully connected via {method_name}")
                        logger.info(f"Successfully connected via {method_name}")
                        return True
                    else:
                        self.debug_info.append(f"❌ {method_name} session test failed")
                else:
                    self.debug_info.append(f"❌ {method_name} session creation failed")
                        
            except Exception as e:
                error_msg = f"Method {method_name} failed: {str(e)}"
                self.debug_info.append(f"❌ {error_msg}")
                logger.warning(error_msg)
                continue
        
        # If all methods fail, set demo mode
        self.demo_mode = True
        self.debug_info.append("❌ All AWS authentication methods failed - switching to demo mode")
        self.connection_status['error'] = "All AWS authentication methods failed"
        self.connection_status['debug_info'] = self.debug_info
        return False
    
    def _try_environment_credentials(self, region: str):
        """Try environment variables with detailed logging"""
        aws_access_key = os.getenv('AWS_ACCESS_KEY_ID')
        aws_secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
        
        if aws_access_key and aws_secret_key:
            self.debug_info.append(f"✅ Found environment variables")
            self.debug_info.append(f"   Access Key: {aws_access_key[:8]}...{aws_access_key[-4:]}")
            self.debug_info.append(f"   Secret Key: {aws_secret_key[:4]}...{aws_secret_key[-4:]}")
            self.debug_info.append(f"   Region: {region}")
            
            # Validate format
            access_key_pattern = r'^(AKIA|ASIA)[0-9A-Z]{16}$'
            if not re.match(access_key_pattern, aws_access_key):
                self.debug_info.append(f"❌ Access key format invalid (expected AKIA/ASIA + 16 chars)")
                return None
                
            if len(aws_secret_key) != 40:
                self.debug_info.append(f"❌ Secret key length invalid (expected 40, got {len(aws_secret_key)})")
                return None
            
            self.debug_info.append("✅ Credential format validation passed")
            
            try:
                session = boto3.Session(
                    aws_access_key_id=aws_access_key,
                    aws_secret_access_key=aws_secret_key,
                    region_name=region
                )
                self.debug_info.append("✅ boto3.Session created successfully")
                return session
            except Exception as e:
                self.debug_info.append(f"❌ boto3.Session creation failed: {str(e)}")
                return None
        else:
            missing = []
            if not aws_access_key:
                missing.append("AWS_ACCESS_KEY_ID")
            if not aws_secret_key:
                missing.append("AWS_SECRET_ACCESS_KEY")
            self.debug_info.append(f"❌ Missing environment variables: {', '.join(missing)}")
            return None
    
    def _try_explicit_credentials(self, access_key: str, secret_key: str, region: str):
        """Try explicit credentials with validation"""
        if not access_key or not secret_key or access_key == 'demo' or secret_key == 'demo':
            self.debug_info.append("❌ No explicit credentials provided or demo values")
            return None
        
        self.debug_info.append(f"🔑 Trying explicit credentials")
        self.debug_info.append(f"   Access Key: {access_key[:8]}...{access_key[-4:]}")
        
        if not self._validate_aws_credentials(access_key, secret_key):
            self.debug_info.append("❌ Explicit credential format validation failed")
            return None
        
        try:
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=region
            )
            self.debug_info.append("✅ Explicit credentials session created")
            return session
        except Exception as e:
            self.debug_info.append(f"❌ Explicit credentials session failed: {str(e)}")
            return None
    
    def _try_shared_credentials(self, region: str):
        """Try shared credentials file"""
        try:
            self.debug_info.append("🔄 Trying shared credentials file")
            session = boto3.Session(region_name=region)
            # Test if credentials are available
            session.client('sts').get_caller_identity()
            self.debug_info.append("✅ Shared credentials work")
            return session
        except Exception as e:
            self.debug_info.append(f"❌ Shared credentials failed: {str(e)}")
            return None
    
    def _try_instance_metadata(self, region: str):
        """Try EC2 instance metadata"""
        try:
            self.debug_info.append("🔄 Trying instance metadata (IAM role)")
            session = boto3.Session(region_name=region)
            # This will work if running on EC2 with IAM role
            session.client('sts').get_caller_identity()
            self.debug_info.append("✅ Instance metadata/IAM role works")
            return session
        except Exception as e:
            self.debug_info.append(f"❌ Instance metadata failed: {str(e)}")
            return None
    
    def _validate_aws_credentials(self, access_key: str, secret_key: str) -> bool:
        """Validate AWS credential format"""
        access_key_pattern = r'^(AKIA|ASIA)[0-9A-Z]{16}$'
        if not re.match(access_key_pattern, access_key):
            self.debug_info.append(f"❌ Access key format invalid: {access_key[:8]}...")
            return False
            
        if len(secret_key) != 40:
            self.debug_info.append(f"❌ Secret key length invalid: {len(secret_key)} (expected 40)")
            return False
            
        self.debug_info.append("✅ Credential format validation passed")
        return True
    
    def _test_session(self, session, method_name: str) -> bool:
        """Test AWS session with comprehensive checks"""
        try:
            self.debug_info.append(f"🧪 Testing session from {method_name}")
            
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
            
            self.debug_info.append(f"✅ STS test passed")
            self.debug_info.append(f"   Account: {identity.get('Account')}")
            self.debug_info.append(f"   User: {identity.get('Arn', 'Unknown')}")
            
            # Store account information
            self.connection_status.update({
                'account_id': identity.get('Account'),
                'user_arn': identity.get('Arn'),
                'region': session.region_name,
                'last_test': datetime.now()
            })
            
            # Test CloudWatch access
            try:
                cloudwatch_client = session.client('cloudwatch', config=config)
                cloudwatch_client.list_metrics(MaxRecords=1)
                self.debug_info.append("✅ CloudWatch access confirmed")
            except Exception as cw_e:
                self.debug_info.append(f"⚠️ CloudWatch access limited: {str(cw_e)}")
            
            return True
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_msg = f"AWS Error ({error_code}): {e.response['Error']['Message']}"
            self.debug_info.append(f"❌ {error_msg}")
            self.connection_status['error'] = error_msg
            return False
        except Exception as e:
            error_msg = f"Connection test failed ({method_name}): {str(e)}"
            self.debug_info.append(f"❌ {error_msg}")
            self.connection_status['error'] = error_msg
            return False
    
    def get_connection_status(self) -> Dict:
        """Get current connection status with debug info"""
        status = self.connection_status.copy()
        status['demo_mode'] = self.demo_mode
        status['streamlit_cloud'] = self.is_streamlit_cloud
        status['debug_info'] = self.debug_info
        return status

# Enhanced display function for debugging
def display_connection_status_with_debug():
    """Enhanced connection status display with debugging"""
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
                            st.error(conn_status['error'])
                            
                            # Show debug information
                            if conn_status.get('debug_info'):
                                with st.expander("🔍 Detailed Debug Information"):
                                    for debug_msg in conn_status['debug_info']:
                                        st.text(debug_msg)
                            
                            # Show Streamlit Cloud specific help
                            if conn_status.get('streamlit_cloud'):
                                with st.expander("☁️ Streamlit Cloud Troubleshooting"):
                                    st.info("""
                                    **Quick Fix for Streamlit Cloud:**
                                    1. Go to your app dashboard
                                    2. Click ⚙️ Settings → Secrets
                                    3. Add these exact lines:
                                    
                                    ```
                                    AWS_ACCESS_KEY_ID = "AKIA..."
                                    AWS_SECRET_ACCESS_KEY = "your-40-char-key"
                                    AWS_DEFAULT_REGION = "us-east-1"
                                    ```
                                    
                                    4. Save and restart your app
                                    5. **Important:** No quotes around values!
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
            
            # Always show debug info if available
            if conn_status.get('debug_info'):
                with st.expander("🐛 Debug Information"):
                    for debug_msg in conn_status['debug_info']:
                        st.text(debug_msg)