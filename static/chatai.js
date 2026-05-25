/* Custom scrollbar for chat */
#chat-container::-webkit-scrollbar { width: 8px; }
#chat-container::-webkit-scrollbar-track { background: #f1f1f1; }
#chat-container::-webkit-scrollbar-thumb { background: #888; border-radius: 4px; }
#chat-container::-webkit-scrollbar-thumb:hover { background: #555; }

/* Message animations */
.message-appear { animation: slideIn 0.3s ease-out; }

@keyframes slideIn {
    from { opacity: 0; transform: translateY(10px); }
    to   { opacity: 1; transform: translateY(0); }
}

/* Typing indicator */
.typing-indicator { display: inline-flex; gap: 4px; padding: 8px 12px; }
.typing-indicator span {
    width: 8px; height: 8px;
    border-radius: 50%;
    background: #999;
    animation: typing 1.4s infinite;
}
.typing-indicator span:nth-child(2) { animation-delay: 0.2s; }
.typing-indicator span:nth-child(3) { animation-delay: 0.4s; }

@keyframes typing {
    0%, 60%, 100% { transform: translateY(0); }
    30%           { transform: translateY(-10px); }
}
