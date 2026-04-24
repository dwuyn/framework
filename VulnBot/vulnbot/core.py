"""
Core VulnBot library - provides programmatic interface to the framework.
"""

import traceback
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, Callable, List
from enum import StrEnum

from pydantic import BaseModel


class RoleType(StrEnum):
    COLLECTOR = "collector"
    SCANNER = "scanner"
    EXPLOITER = "exploiter"


@dataclass
class ModelConfig:
    """LLM Model configuration."""
    api_key: str = ""
    base_url: str = "https://api.openai.com/v1"
    llm_model: str = "openai"  # "openai" or "ollama"
    llm_model_name: str = "gpt-4"
    temperature: float = 0.7
    context_length: int = 8192
    timeout: int = 120
    history_len: int = 10
    # Embedding config (for RAG)
    embedding_models: str = "text-embedding-ada-002"
    embedding_type: str = "remote"
    embedding_url: str = "https://api.openai.com/v1/embeddings"


@dataclass
class KaliConfig:
    """Kali Linux SSH connection configuration."""
    hostname: str = "127.0.0.1"
    port: int = 22
    username: str = "kali"
    password: str = "kali"


@dataclass 
class DatabaseConfig:
    """MySQL database configuration."""
    host: str = "localhost"
    port: int = 3306
    user: str = ""
    password: str = ""
    database: str = "vulnbot"


@dataclass
class RAGConfig:
    """RAG (Retrieval-Augmented Generation) configuration."""
    enabled: bool = False
    kb_name: str = ""
    milvus_uri: str = ""
    milvus_user: str = ""
    milvus_password: str = ""
    top_k: int = 3
    top_n: int = 1
    score_threshold: float = 0.5


@dataclass
class VulnBotConfig:
    """Complete VulnBot configuration."""
    model: ModelConfig = field(default_factory=ModelConfig)
    kali: KaliConfig = field(default_factory=KaliConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    rag: RAGConfig = field(default_factory=RAGConfig)
    
    # Runtime options
    max_interactions: int = 5
    mode: str = "auto"  # "auto", "manual", "semi"
    log_verbose: bool = True
    log_path: str = "./logs"

    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> "VulnBotConfig":
        """Create config from a dictionary."""
        cfg = cls()
        
        if "model" in config_dict or "model_config" in config_dict:
            model_data = config_dict.get("model", config_dict.get("model_config", {}))
            cfg.model = ModelConfig(**{k: v for k, v in model_data.items() 
                                       if hasattr(ModelConfig, k) or k in ModelConfig.__dataclass_fields__})
        
        if "kali" in config_dict or "kali_config" in config_dict:
            kali_data = config_dict.get("kali", config_dict.get("kali_config", {}))
            cfg.kali = KaliConfig(**kali_data)
        
        if "database" in config_dict or "db_config" in config_dict:
            db_data = config_dict.get("database", config_dict.get("db_config", {}))
            cfg.database = DatabaseConfig(**db_data)
        
        if "rag" in config_dict or "rag_config" in config_dict:
            rag_data = config_dict.get("rag", config_dict.get("rag_config", {}))
            cfg.rag = RAGConfig(**rag_data)
        
        # Top-level options
        if "max_interactions" in config_dict:
            cfg.max_interactions = config_dict["max_interactions"]
        if "mode" in config_dict:
            cfg.mode = config_dict["mode"]
        if "log_verbose" in config_dict:
            cfg.log_verbose = config_dict["log_verbose"]
        if "log_path" in config_dict:
            cfg.log_path = config_dict["log_path"]
            
        return cfg


class SessionResult(BaseModel):
    """Result from a VulnBot session."""
    success: bool = False
    session_id: Optional[str] = None
    phases_completed: List[str] = []
    error: Optional[str] = None
    summary: Optional[str] = None


class VulnBot:
    """
    Main VulnBot interface for programmatic penetration testing.
    
    Example:
        bot = VulnBot(
            model_config={
                "api_key": "sk-...",
                "llm_model_name": "gpt-4",
            },
            kali_config={
                "hostname": "192.168.1.100",
                "username": "kali",
                "password": "kali",
            }
        )
        
        result = bot.run("Pentest target at 10.0.2.5")
    """
    
    def __init__(
        self,
        config: Optional[VulnBotConfig] = None,
        model_config: Optional[Dict[str, Any]] = None,
        kali_config: Optional[Dict[str, Any]] = None,
        db_config: Optional[Dict[str, Any]] = None,
        rag_config: Optional[Dict[str, Any]] = None,
        max_interactions: int = 5,
        mode: str = "auto",
        on_phase_start: Optional[Callable[[str], None]] = None,
        on_phase_complete: Optional[Callable[[str, Any], None]] = None,
        on_task_execute: Optional[Callable[[str, str], None]] = None,
        on_llm_response: Optional[Callable[[str], None]] = None,
    ):
        """
        Initialize VulnBot.
        
        Args:
            config: Complete VulnBotConfig object (alternative to individual configs)
            model_config: LLM configuration dict
            kali_config: Kali SSH connection config dict
            db_config: Database configuration dict
            rag_config: RAG configuration dict
            max_interactions: Max interactions per role/phase
            mode: Execution mode ("auto", "manual", "semi")
            on_phase_start: Callback when a phase starts (phase_name)
            on_phase_complete: Callback when a phase completes (phase_name, result)
            on_task_execute: Callback when a task executes (task_description, command)
            on_llm_response: Callback when LLM responds (response_text)
        """
        if config is not None:
            self.config = config
        else:
            # Build config from individual dicts
            config_dict = {}
            if model_config:
                config_dict["model_config"] = model_config
            if kali_config:
                config_dict["kali_config"] = kali_config
            if db_config:
                config_dict["db_config"] = db_config
            if rag_config:
                config_dict["rag_config"] = rag_config
            config_dict["max_interactions"] = max_interactions
            config_dict["mode"] = mode
            
            self.config = VulnBotConfig.from_dict(config_dict)
        
        # Callbacks
        self.on_phase_start = on_phase_start
        self.on_phase_complete = on_phase_complete
        self.on_task_execute = on_task_execute
        self.on_llm_response = on_llm_response
        
        self._initialized = False
        self._console = None
    
    def _apply_config(self):
        """Apply runtime config to the framework's global Configs."""
        from config.config import Configs
        
        # Apply model config
        Configs.llm_config.api_key = self.config.model.api_key
        Configs.llm_config.base_url = self.config.model.base_url
        Configs.llm_config.llm_model = self.config.model.llm_model
        Configs.llm_config.llm_model_name = self.config.model.llm_model_name
        Configs.llm_config.temperature = self.config.model.temperature
        Configs.llm_config.context_length = self.config.model.context_length
        Configs.llm_config.timeout = self.config.model.timeout
        Configs.llm_config.history_len = self.config.model.history_len
        Configs.llm_config.embedding_models = self.config.model.embedding_models
        Configs.llm_config.embedding_type = self.config.model.embedding_type
        Configs.llm_config.embedding_url = self.config.model.embedding_url
        
        # Apply Kali config
        Configs.basic_config.kali = {
            "hostname": self.config.kali.hostname,
            "port": self.config.kali.port,
            "username": self.config.kali.username,
            "password": self.config.kali.password,
        }
        
        # Apply basic config
        Configs.basic_config.mode = self.config.mode
        Configs.basic_config.log_verbose = self.config.log_verbose
        Configs.basic_config.enable_rag = self.config.rag.enabled
        
        # Apply RAG config if enabled
        if self.config.rag.enabled:
            Configs.kb_config.kb_name = self.config.rag.kb_name
            Configs.kb_config.milvus = {
                "uri": self.config.rag.milvus_uri,
                "user": self.config.rag.milvus_user,
                "password": self.config.rag.milvus_password,
            }
            Configs.kb_config.top_k = self.config.rag.top_k
            Configs.kb_config.top_n = self.config.rag.top_n
            Configs.kb_config.score_threshold = self.config.rag.score_threshold
        
        # Apply database config
        Configs.db_config.mysql = {
            "host": self.config.database.host,
            "port": self.config.database.port,
            "user": self.config.database.user,
            "password": self.config.database.password,
            "database": self.config.database.database,
        }
    
    def _init_framework(self):
        """Initialize the VulnBot framework."""
        if self._initialized:
            return
            
        from config.config import Configs
        from utils.session import create_tables
        from rich.console import Console
        
        # Ensure directories exist
        Configs.basic_config.make_dirs()
        
        # Create database tables
        create_tables()
        
        # Apply our runtime config
        self._apply_config()
        
        self._console = Console()
        self._initialized = True
    
    def run(
        self, 
        target_description: str,
        start_role: str = "collector",
        session_id: Optional[str] = None,
    ) -> SessionResult:
        """
        Run a penetration testing session.
        
        Args:
            target_description: Description of the penetration testing target/task
            start_role: Which role to start with ("collector", "scanner", "exploiter")
            session_id: Optional existing session ID to resume
            
        Returns:
            SessionResult with success status and details
        """
        self._init_framework()
        
        from db.models.session_model import Session
        from db.repository.session_repository import add_session_to_db
        from db.repository.plan_repository import get_planner_by_id
        from roles.collector import Collector
        from roles.scanner import Scanner
        from roles.exploiter import Exploiter
        from actions.shell_manager import ShellManager
        from utils.log_common import RoleType as FrameworkRoleType
        
        roles_map = {
            "collector": (Collector, FrameworkRoleType.COLLECTOR.value),
            "scanner": (Scanner, FrameworkRoleType.SCANNER.value),
            "exploiter": (Exploiter, FrameworkRoleType.EXPLOITER.value),
        }
        
        result = SessionResult()
        
        try:
            # Create or load session
            if session_id:
                from db.repository.session_repository import fetch_session_by_id
                session = fetch_session_by_id(session_id)
                if not session:
                    result.error = f"Session {session_id} not found"
                    return result
            else:
                role_cls, role_name = roles_map.get(start_role, (Collector, FrameworkRoleType.COLLECTOR.value))
                session = Session(
                    current_role_name=role_name,
                    init_description=target_description,
                    current_planner_id='',
                    history_planner_ids=[]
                )
            
            result.session_id = session.id
            
            # Get the role class
            role_cls, _ = roles_map.get(session.current_role_name, (Collector, FrameworkRoleType.COLLECTOR.value))
            
            # Notify phase start
            if self.on_phase_start:
                self.on_phase_start(session.current_role_name)
            
            # Run the role
            current_role = role_cls(self._console, self.config.max_interactions)
            current_role.run(session)
            
            result.phases_completed.append(session.current_role_name)
            
            # Notify phase complete
            if self.on_phase_complete:
                self.on_phase_complete(session.current_role_name, None)
            
            # Save session
            add_session_to_db(session_data=session)
            result.session_id = session.id
            result.success = True
            
        except Exception as e:
            result.error = str(e)
            result.success = False
            
        finally:
            # Clean up SSH connection
            try:
                ShellManager.get_instance().close()
            except:
                pass
        
        return result
    
    def run_single_phase(
        self,
        target_description: str,
        role: str = "collector",
    ) -> SessionResult:
        """
        Run only a single phase (role) without automatic progression.
        
        Args:
            target_description: Description of the target
            role: Which role to run ("collector", "scanner", "exploiter")
            
        Returns:
            SessionResult with phase results
        """
        # This runs only the specified role without chaining to the next
        return self.run(target_description, start_role=role)
    
    def chat(
        self,
        query: str,
        conversation_id: Optional[str] = None,
    ) -> str:
        """
        Direct chat with the LLM (for custom queries).
        
        Args:
            query: The query to send to the LLM
            conversation_id: Optional conversation ID for history
            
        Returns:
            LLM response text
        """
        self._init_framework()
        
        from server.chat.chat import _chat
        
        if conversation_id:
            return _chat(query=query, conversation_id=conversation_id)
        else:
            response, conv_id = _chat(query=query)
            return response
    
    def execute_command(self, command: str) -> str:
        """
        Execute a shell command on the Kali machine.
        
        Args:
            command: Shell command to execute
            
        Returns:
            Command output
        """
        self._init_framework()
        
        from actions.shell_manager import ShellManager
        
        shell = ShellManager.get_instance().get_shell()
        return shell.execute_cmd(command)
    
    def close(self):
        """Close all connections and clean up resources."""
        from actions.shell_manager import ShellManager
        try:
            ShellManager.get_instance().close()
        except:
            pass
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
