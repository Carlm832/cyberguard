import os
print('GEMINI_API_KEY=', bool(os.getenv('GEMINI_API_KEY')))
print('OPEN_ROUTER_API_KEY=', bool(os.getenv('OPEN_ROUTER_API_KEY')))
print('OPEN_ROUTER_CHAT_MODEL=', os.getenv('OPEN_ROUTER_CHAT_MODEL'))
print('GEMINI_MODEL=', os.getenv('GEMINI_MODEL'))
