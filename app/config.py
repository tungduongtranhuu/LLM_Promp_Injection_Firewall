import os
from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")
block_threshold = int(os.getenv("BLOCK_THRESHOLD"))
warn_threshold = int(os.getenv("WARN_THRESHOLD"))

