from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    host: str = "127.0.0.1"
    port: int = 8088

    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_router_model: str = "qwen3:8b"
    ollama_deep_model: str = "qwen3:32b"

    max_swap_bytes: int = 0
    max_mem_percent: float = 92.0

    heavy_slot_concurrency: int = 1

    audit_log_path: str = "./audit.log"
    edr_root_path: str = "./artifacts/edr"

    anthropic_api_key: str | None = None
    openai_api_key: str | None = None


settings = Settings()
