import httpx


async def ollama_chat(base_url: str, model: str, messages: list[dict], stream: bool = False) -> dict:
    payload = {"model": model, "messages": messages, "stream": stream}
    async with httpx.AsyncClient(timeout=300.0) as client:
        response = await client.post(f"{base_url}/api/chat", json=payload)
        response.raise_for_status()
        return response.json()
